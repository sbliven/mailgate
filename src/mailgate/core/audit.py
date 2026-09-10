"""Append-only, hash-chained audit log.

Design notes that came out of review:

* The per-session HMAC is **gone**.  If the MAC key lives in the server's own
  session memory, a same-user attacker starts a fresh session, forges an entire
  chain with a new key, and ``verify`` cannot tell.  Integrity here rests on the
  hash chain plus an *external* anchor, and that is stated rather than implied.
* The head hash is anchored **before** each mutation executes, so an unanchored
  tail is itself the alarm and ``verify`` can report its length.  "Anchor every N
  records" leaves an N-record window that ``kill -9`` opens.
* Month files are chained: each new month opens with an explicit continuation
  record carrying the previous file's head, so deleting a whole month is visible.
* Each record is one ``write()`` of a complete newline-terminated line followed by
  ``fsync``, and ``verify`` distinguishes a torn tail (recoverable) from tampering.
* Bodies are never logged.  Subjects are hashed over **raw bytes** -- hashing the
  normalised form would not match the real subject during forensics.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import datetime as dt
import os
import shutil
import subprocess
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

from .mailstate import canonical_json, sha256_hex
from .secfs import check_secure_path, open_append_nofollow, secure_mkdir
from .store import Store

RECORD_VERSION = 1
GENESIS = "0" * 64


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


@dataclass
class VerifyResult:
    ok: bool
    records: int
    files: list[str]
    problems: list[str]
    incomplete_tail: bool = False
    unanchored_tail: int = 0

    def summary(self) -> str:
        if self.ok and not self.problems:
            return f"chain OK: {self.records} records across {len(self.files)} file(s)"
        return f"chain PROBLEMS ({self.records} records): " + "; ".join(self.problems)


class AuditLog:
    def __init__(self, base_dir: str | Path, store: Store, *, anchor: bool = True):
        self.dir = secure_mkdir(Path(base_dir))
        self.store = store
        self.anchor_enabled = anchor
        self.anchor_path = self.dir / "anchor.log"
        self.head_path = self.dir / "HEAD"
        self.session = uuid.uuid4().hex
        seq, head, file = store.get_chain()
        self.seq = seq
        self.head = head or GENESIS
        self.last_file = file
        self._unanchored = 0
        # append() advances (seq, head); the broker thread appends too.
        self._lk = threading.RLock()

    # ------------------------------------------------------------------ #
    def _month_file(self) -> Path:
        return self.dir / (dt.datetime.now(dt.timezone.utc).strftime("%Y-%m") + ".jsonl")

    def _write_line(self, path: Path, payload: dict) -> str:
        """Write one record atomically-ish and return its hash."""
        rec = dict(payload)
        rec["v"] = RECORD_VERSION
        rec["seq"] = self.seq + 1
        rec["prev"] = self.head
        rec.setdefault("ts", _now_iso())
        rec.setdefault("session", self.session)
        line = canonical_json(rec) + b"\n"
        digest = sha256_hex(canonical_json(rec))
        fd = open_append_nofollow(path)
        try:
            os.write(fd, line)          # single write of a complete line
            os.fsync(fd)
        finally:
            os.close(fd)
        self.seq += 1
        self.head = digest
        self.last_file = path.name
        self.store.set_chain(self.seq, self.head, self.last_file)
        self.head_path.write_text(f"{self.seq} {self.head} {self.last_file}\n")
        os.chmod(self.head_path, 0o600)
        self._unanchored += 1
        return digest

    def append(self, **payload) -> str:
        """Append a record; returns its audit id (``<seq>:<hash12>``)."""
        with self._lk:
            return self._append_locked(**payload)

    def _append_locked(self, **payload) -> str:
        path = self._month_file()
        if not path.exists() and self.head != GENESIS:
            # month rollover: chain the new file to the old one explicitly
            self._write_line(
                path,
                {
                    "type": "chain_continuation",
                    "prev_file": self.last_file,
                    "prev_head": self.head,
                },
            )
        digest = self._write_line(path, payload)
        return f"{self.seq}:{digest[:12]}"

    # ------------------------------------------------------------------ #
    def anchor_now(self, note: str = "") -> None:
        """Publish the head hash outside the log's own file.

        Called BEFORE every mutation.  journald is preferred because the agent
        cannot rewrite it; the local anchor file is a fallback that at least makes
        wholesale rewriting harder to do consistently.
        """
        if not self.anchor_enabled:
            return
        with self._lk:
            seq, head = self.seq, self.head
        msg = f"mailgate-anchor seq={seq} head={head} session={self.session} {note}"
        cat = shutil.which("systemd-cat")
        if cat:
            try:
                subprocess.run(
                    [cat, "-t", "mailgate", "-p", "notice"],
                    input=msg.encode(),
                    timeout=5,
                    check=False,
                    stderr=subprocess.DEVNULL,
                )
            except (OSError, subprocess.SubprocessError):
                pass
        fd = open_append_nofollow(self.anchor_path)
        try:
            os.write(fd, (msg + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        self._unanchored = 0

    @property
    def unanchored(self) -> int:
        return self._unanchored

    # ------------------------------------------------------------------ #
    def verify(self) -> VerifyResult:
        files = sorted(p for p in self.dir.glob("*.jsonl"))
        problems: list[str] = []
        n = 0
        prev_hash = GENESIS
        prev_seq = 0
        incomplete = False
        for path in files:
            check_secure_path(path, mode_max=0o600)
            raw = path.read_bytes()
            if raw and not raw.endswith(b"\n"):
                incomplete = True
                problems.append(f"{path.name}: torn final line (recoverable: truncate to last \\n)")
                raw = raw[: raw.rfind(b"\n") + 1]
            for lineno, line in enumerate(raw.splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    import json

                    rec = json.loads(line)
                except ValueError:
                    problems.append(f"{path.name}:{lineno}: not valid JSON")
                    continue
                if rec.get("v") != RECORD_VERSION:
                    problems.append(
                        f"{path.name}:{lineno}: record version {rec.get('v')} unsupported"
                    )
                    continue
                if rec.get("prev") != prev_hash:
                    problems.append(
                        f"{path.name}:{lineno}: prev mismatch (chain broken at seq {rec.get('seq')})"
                    )
                if rec.get("seq") != prev_seq + 1:
                    problems.append(
                        f"{path.name}:{lineno}: seq gap ({prev_seq} -> {rec.get('seq')})"
                    )
                # recompute this record's hash exactly as _write_line did
                prev_hash = sha256_hex(canonical_json(rec))
                prev_seq = rec.get("seq", prev_seq + 1)
                n += 1
        db_seq, db_head, _ = self.store.get_chain()
        if n and (db_seq, db_head) != (prev_seq, prev_hash):
            problems.append(
                f"state db head ({db_seq}, {db_head[:12]}) disagrees with the log "
                f"({prev_seq}, {prev_hash[:12]}): records were removed or the db was rolled back"
            )
        anchored = self._last_anchor_seq()
        unanchored = max(0, prev_seq - anchored)
        if unanchored > 1:
            problems.append(
                f"{unanchored} record(s) after the last external anchor (seq {anchored}) -- "
                "this tail is not independently attested"
            )
        return VerifyResult(
            ok=not problems,
            records=n,
            files=[p.name for p in files],
            problems=problems,
            incomplete_tail=incomplete,
            unanchored_tail=unanchored,
        )

    def _last_anchor_seq(self) -> int:
        if not self.anchor_path.exists():
            return 0
        best = 0
        for line in self.anchor_path.read_text().splitlines():
            for tok in line.split():
                if tok.startswith("seq="):
                    try:
                        best = max(best, int(tok[4:]))
                    except ValueError:
                        pass
        return best
