"""SQLite state: budgets, idempotency, locks, aliases, reconciliation queue.

Everything here is keyed on **resolved mailbox identity**, never on the config
alias -- two aliases pointing at one mailbox would otherwise double every budget
and let two adapters race the same folder.

Budgets are persisted with wall-clock windows plus a boot id.  Monotonic clocks are
right for in-process TTLs and useless for persisted windows (they reset per boot),
and per-session counters are useless against an agent that can respawn the server.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import contextlib
import fcntl
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..errors import MailgateError
from .mailstate import canonical_json, sha256_hex
from .secfs import secure_mkdir

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS chain (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    seq INTEGER NOT NULL,
    head TEXT NOT NULL,
    file TEXT NOT NULL
);

-- Two-phase idempotency.  The row is committed and fsynced BEFORE the provider
-- call, so a lost response leaves an in_flight row to reconcile rather than a gap
-- that a retry would happily double-apply.
CREATE TABLE IF NOT EXISTS idem (
    mailbox TEXT NOT NULL,
    idem_key TEXT NOT NULL,
    op TEXT NOT NULL,
    request_fp TEXT NOT NULL,
    state TEXT NOT NULL,            -- in_flight | terminal
    status TEXT,                    -- the Status value once terminal
    audit_id TEXT,
    result TEXT,
    created_ts REAL NOT NULL,
    updated_ts REAL NOT NULL,
    PRIMARY KEY (mailbox, idem_key)
);

-- Server-derived fingerprint, deduped independently of the agent's key: an LLM
-- that regenerates a UUID on retry must not defeat idempotency.
CREATE TABLE IF NOT EXISTS request_fp (
    mailbox TEXT NOT NULL,
    request_fp TEXT NOT NULL,
    idem_key TEXT NOT NULL,
    created_ts REAL NOT NULL,
    PRIMARY KEY (mailbox, request_fp)
);

CREATE TABLE IF NOT EXISTS counters (
    mailbox TEXT NOT NULL,
    bucket TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (mailbox, bucket, window_start)
);

CREATE TABLE IF NOT EXISTS message_touch (
    mailbox TEXT NOT NULL,
    message_key TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (mailbox, message_key, window_start)
);

CREATE TABLE IF NOT EXISTS sender_touch (
    mailbox TEXT NOT NULL,
    sender_hash TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (mailbox, sender_hash, window_start)
);

-- IMAP COPY-without-remove leaves a duplicate that nothing may retry and undo
-- cannot remove (that would need a delete verb).  Tracked, capped, reconciled.
CREATE TABLE IF NOT EXISTS copy_pending (
    mailbox TEXT NOT NULL,
    message_key TEXT NOT NULL,
    src TEXT NOT NULL,
    dest TEXT NOT NULL,
    dest_uid INTEGER,
    audit_id TEXT NOT NULL,
    created_ts REAL NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (mailbox, message_key, audit_id)
);

-- Graph ids change on move; undo and per-run brakes must still resolve.
CREATE TABLE IF NOT EXISTS id_alias (
    mailbox TEXT NOT NULL,
    old_id TEXT NOT NULL,
    new_id TEXT NOT NULL,
    created_ts REAL NOT NULL,
    PRIMARY KEY (mailbox, old_id)
);

CREATE TABLE IF NOT EXISTS undone (
    audit_id TEXT PRIMARY KEY,
    undo_audit_id TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS label_pin (
    mailbox TEXT NOT NULL,
    label_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    PRIMARY KEY (mailbox, label_id)
);

CREATE TABLE IF NOT EXISTS standing_rules (
    id TEXT PRIMARY KEY,
    mailbox TEXT NOT NULL,
    pattern TEXT NOT NULL,
    op TEXT NOT NULL,
    target TEXT NOT NULL,
    expires_ts REAL NOT NULL,
    max_uses INTEGER NOT NULL,
    uses INTEGER NOT NULL DEFAULT 0,
    created_ts REAL NOT NULL
);
"""


class ClockWentBackwards(MailgateError):
    code = "clock_went_backwards"


@dataclass(frozen=True)
class BudgetVerdict:
    ok: bool
    bucket: str = ""
    used: int = 0
    limit: int = 0

    @property
    def reason(self) -> str:
        return f"{self.bucket} budget exhausted ({self.used}/{self.limit})"


def boot_id() -> str:
    for p in ("/proc/sys/kernel/random/boot_id",):
        try:
            return Path(p).read_text().strip()
        except OSError:
            continue
    return "unknown-boot"


class Store:
    def __init__(self, state_dir: str | Path):
        self.dir = secure_mkdir(Path(state_dir))
        self.db_path = self.dir / "state.sqlite3"
        first = not self.db_path.exists()
        # check_same_thread=False + an RLock: the approval broker executes mutations
        # on its own thread, so every store method is serialised explicitly.
        self._lk = threading.RLock()
        self.cx = sqlite3.connect(
            self.db_path, isolation_level=None, timeout=30, check_same_thread=False
        )
        if first:
            os.chmod(self.db_path, 0o600)
        self.cx.row_factory = sqlite3.Row
        self.cx.execute("PRAGMA journal_mode=WAL")
        self.cx.execute("PRAGMA synchronous=FULL")
        self.cx.execute("PRAGMA foreign_keys=ON")
        self.cx.executescript(_SCHEMA)
        self._init_meta()
        self._check_clock()

    # ---------------- meta / migrations ----------------
    def _init_meta(self) -> None:
        row = self.cx.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
        if row is None:
            self.cx.execute(
                "INSERT INTO meta(k,v) VALUES('schema_version',?)", (str(SCHEMA_VERSION),)
            )
        elif int(row["v"]) != SCHEMA_VERSION:
            raise MailgateError(
                f"state db schema {row['v']} != {SCHEMA_VERSION}; run `mailgate migrate`",
                code="schema_mismatch",
            )

    def _check_clock(self) -> None:
        """A backwards clock jump must refuse mutations, not reset the window."""
        now = time.time()
        row = self.cx.execute("SELECT v FROM meta WHERE k='last_wall'").fetchone()
        bid = boot_id()
        brow = self.cx.execute("SELECT v FROM meta WHERE k='boot_id'").fetchone()
        self.clock_suspect = False
        if row is not None and float(row["v"]) - now > 5.0:
            # tolerate NTP nudges; a real jump is seconds-to-hours
            self.clock_suspect = True
        self.cx.execute(
            "INSERT INTO meta(k,v) VALUES('last_wall',?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (str(now),),
        )
        self.cx.execute(
            "INSERT INTO meta(k,v) VALUES('boot_id',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (bid,),
        )
        self.boot_id = bid
        self.prev_boot_id = brow["v"] if brow else bid

    @contextlib.contextmanager
    def tx(self):
        self.cx.execute("BEGIN IMMEDIATE")
        try:
            yield self.cx
        except Exception:
            self.cx.execute("ROLLBACK")
            raise
        else:
            self.cx.execute("COMMIT")

    # ---------------- account lock ----------------
    @contextlib.contextmanager
    def account_lock(self, mailbox_key: str, *, blocking: bool = False):
        """flock on a per-mailbox lockfile.

        A file lock, not an in-process one: `mailgate undo` and every other CLI
        mutator is a separate process and must contend for the same lock.
        """
        safe = sha256_hex(mailbox_key.encode())[:32]
        lock_path = self.dir / f"lock-{safe}"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX if blocking else (fcntl.LOCK_EX | fcntl.LOCK_NB))
        except BlockingIOError:
            os.close(fd)
            raise MailgateError("another writer holds this mailbox", code="account_busy") from None
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    # ---------------- chain head ----------------
    def get_chain(self) -> tuple[int, str, str]:
        row = self.cx.execute("SELECT seq, head, file FROM chain WHERE id=1").fetchone()
        if row is None:
            return 0, "0" * 64, ""
        return row["seq"], row["head"], row["file"]

    def set_chain(self, seq: int, head: str, file: str) -> None:
        self.cx.execute(
            "INSERT INTO chain(id,seq,head,file) VALUES(1,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET seq=excluded.seq, head=excluded.head, file=excluded.file",
            (seq, head, file),
        )

    # ---------------- budgets ----------------
    def _bump(self, table: str, keycols: tuple[str, ...], keyvals: tuple, window: int, limit: int,
              *, dry: bool = False) -> BudgetVerdict:
        cols = ", ".join(keycols)
        qs = ", ".join("?" * len(keyvals))
        where = " AND ".join(f"{c}=?" for c in keycols)
        row = self.cx.execute(
            f"SELECT count FROM {table} WHERE {where} AND window_start=?", (*keyvals, window)
        ).fetchone()
        used = row["count"] if row else 0
        if used >= limit:
            return BudgetVerdict(False, keyvals[-1] if len(keyvals) > 1 else table, used, limit)
        if not dry:
            self.cx.execute(
                f"INSERT INTO {table}({cols}, window_start, count) VALUES({qs}, ?, 1) "
                f"ON CONFLICT({cols}, window_start) DO UPDATE SET count = count + 1",
                (*keyvals, window),
            )
        return BudgetVerdict(True, keyvals[-1] if len(keyvals) > 1 else table, used + 1, limit)

    def charge(self, mailbox: str, bucket: str, limit: int, *, period_s: int = 3600,
               dry: bool = False) -> BudgetVerdict:
        if self.clock_suspect:
            raise ClockWentBackwards(
                "system clock moved backwards; refusing mutations until the window is "
                "re-established (run `mailgate doctor --reset-clock` after checking NTP)"
            )
        window = int(time.time()) // period_s
        v = self._bump("counters", ("mailbox", "bucket"), (mailbox, bucket), window, limit, dry=dry)
        return BudgetVerdict(v.ok, bucket, v.used, limit)

    def charge_message(self, mailbox: str, message_key: str, limit: int = 1,
                       period_s: int = 3600) -> BudgetVerdict:
        window = int(time.time()) // period_s
        v = self._bump(
            "message_touch", ("mailbox", "message_key"), (mailbox, message_key), window, limit
        )
        return BudgetVerdict(v.ok, "per-message", v.used, limit)

    def charge_sender(self, mailbox: str, sender_hash: str, limit: int,
                      period_s: int = 3600) -> BudgetVerdict:
        window = int(time.time()) // period_s
        v = self._bump(
            "sender_touch", ("mailbox", "sender_hash"), (mailbox, sender_hash), window, limit
        )
        return BudgetVerdict(v.ok, "same-sender", v.used, limit)

    # ---------------- idempotency ----------------
    @staticmethod
    def request_fingerprint(mailbox: str, op: str, message_key: str, target: dict) -> str:
        """Fingerprint of the caller's INTENT.

        Deliberately excludes the observed prior state: a retry after a successful
        apply would otherwise hash differently and be misreported as key reuse
        instead of as the duplicate it is.  TOCTOU is handled by the separate
        compare-and-set on ``precondition``, which is where it belongs.
        """
        return sha256_hex(
            canonical_json({"m": mailbox, "o": op, "k": message_key, "t": target})
        )

    def begin_mutation(self, mailbox: str, idem_key: str, op: str, request_fp: str) -> dict:
        """Two-phase step 1.  Returns {'proceed': bool, ...}."""
        now = time.time()
        row = self.cx.execute(
            "SELECT * FROM idem WHERE mailbox=? AND idem_key=?", (mailbox, idem_key)
        ).fetchone()
        if row is not None:
            if row["request_fp"] != request_fp:
                return {"proceed": False, "verdict": "idempotency_key_reuse"}
            if row["state"] == "terminal":
                return {
                    "proceed": False,
                    "verdict": "duplicate_ignored",
                    "original_status": row["status"],
                    "audit_id": row["audit_id"],
                    "result": row["result"],
                }
            return {"proceed": False, "verdict": "in_flight", "audit_id": row["audit_id"]}
        fprow = self.cx.execute(
            "SELECT idem_key FROM request_fp WHERE mailbox=? AND request_fp=?", (mailbox, request_fp)
        ).fetchone()
        if fprow is not None:
            prev = self.cx.execute(
                "SELECT * FROM idem WHERE mailbox=? AND idem_key=?", (mailbox, fprow["idem_key"])
            ).fetchone()
            return {
                "proceed": False,
                "verdict": "duplicate_ignored",
                "original_status": prev["status"] if prev else None,
                "audit_id": prev["audit_id"] if prev else None,
                "note": "server-side fingerprint matched an earlier request",
            }
        self.cx.execute(
            "INSERT INTO idem(mailbox,idem_key,op,request_fp,state,created_ts,updated_ts) "
            "VALUES(?,?,?,?,'in_flight',?,?)",
            (mailbox, idem_key, op, request_fp, now, now),
        )
        self.cx.execute(
            "INSERT OR IGNORE INTO request_fp(mailbox,request_fp,idem_key,created_ts) "
            "VALUES(?,?,?,?)",
            (mailbox, request_fp, idem_key, now),
        )
        # fsync before the provider call: this is the whole point of two-phase.
        self.cx.execute("PRAGMA wal_checkpoint(FULL)")
        return {"proceed": True}

    def finish_mutation(self, mailbox: str, idem_key: str, status: str, audit_id: str,
                        result: str = "") -> None:
        self.cx.execute(
            "UPDATE idem SET state='terminal', status=?, audit_id=?, result=?, updated_ts=? "
            "WHERE mailbox=? AND idem_key=?",
            (status, audit_id, result, time.time(), mailbox, idem_key),
        )

    def in_flight(self) -> list[sqlite3.Row]:
        return list(self.cx.execute("SELECT * FROM idem WHERE state='in_flight'"))

    # ---------------- misc ----------------
    def add_copy_pending(self, mailbox: str, message_key: str, src: str, dest: str,
                         dest_uid: int | None, audit_id: str) -> int:
        self.cx.execute(
            "INSERT OR REPLACE INTO copy_pending"
            "(mailbox,message_key,src,dest,dest_uid,audit_id,created_ts) VALUES(?,?,?,?,?,?,?)",
            (mailbox, message_key, src, dest, dest_uid, audit_id, time.time()),
        )
        return self.count_copy_pending(mailbox)

    def count_copy_pending(self, mailbox: str) -> int:
        return self.cx.execute(
            "SELECT COUNT(*) c FROM copy_pending WHERE mailbox=? AND resolved=0", (mailbox,)
        ).fetchone()["c"]

    def add_id_alias(self, mailbox: str, old_id: str, new_id: str) -> None:
        self.cx.execute(
            "INSERT OR REPLACE INTO id_alias(mailbox,old_id,new_id,created_ts) VALUES(?,?,?,?)",
            (mailbox, old_id, new_id, time.time()),
        )

    def resolve_alias(self, mailbox: str, any_id: str) -> str:
        row = self.cx.execute(
            "SELECT new_id FROM id_alias WHERE mailbox=? AND old_id=?", (mailbox, any_id)
        ).fetchone()
        return row["new_id"] if row else any_id

    def pin_labels(self, mailbox: str, labels: dict[str, str]) -> list[str]:
        """Pin label id -> display name; report drift.

        A label renamed by anyone with mailbox access would otherwise silently
        re-point an allowlist entry at a different label.
        """
        drift = []
        for lid, name in labels.items():
            row = self.cx.execute(
                "SELECT display_name FROM label_pin WHERE mailbox=? AND label_id=?", (mailbox, lid)
            ).fetchone()
            if row is None:
                self.cx.execute(
                    "INSERT INTO label_pin(mailbox,label_id,display_name) VALUES(?,?,?)",
                    (mailbox, lid, name),
                )
            elif row["display_name"] != name:
                drift.append(f"{lid}: {row['display_name']!r} -> {name!r}")
        return drift

    def mark_undone(self, audit_id: str, undo_audit_id: str) -> bool:
        try:
            self.cx.execute(
                "INSERT INTO undone(audit_id,undo_audit_id,ts) VALUES(?,?,?)",
                (audit_id, undo_audit_id, time.time()),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def is_undone(self, audit_id: str) -> bool:
        return (
            self.cx.execute("SELECT 1 FROM undone WHERE audit_id=?", (audit_id,)).fetchone()
            is not None
        )

    def new_session(self) -> str:
        return uuid.uuid4().hex

    def close(self) -> None:
        self.cx.close()


def _synchronized(fn):
    def wrap(self, *a, **k):
        with self._lk:
            return fn(self, *a, **k)

    wrap.__name__ = fn.__name__
    wrap.__doc__ = fn.__doc__
    return wrap


# Context managers are excluded: account_lock uses flock and no sqlite handle.
for _name in (
    "get_chain", "set_chain", "charge", "charge_message", "charge_sender",
    "begin_mutation", "finish_mutation", "in_flight", "add_copy_pending",
    "count_copy_pending", "add_id_alias", "resolve_alias", "pin_labels",
    "mark_undone", "is_undone",
):
    setattr(Store, _name, _synchronized(getattr(Store, _name)))
