"""Fixture backend.  The default, and the only one enabled out of the box.

It models the awkward parts of the real providers on purpose: special-use
attributes that disagree with display names, Gmail-style label state, IMAP
UID/UIDVALIDITY coordinates, shared namespaces, folders with server-side rules,
absent and duplicated Message-IDs, and a UIDVALIDITY bump that can be triggered
mid-run to prove the stale-handle path works.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..core.mailstate import (
    MessageState,
    StateDelta,
    apply_delta_to_state,
    message_key,
    sha256_hex,
)
from ..errors import BackendError, StaleHandle
from ..folders import FolderInfo, LabelInfo, MailboxIdentity
from ..sanitize import safe_address, safe_header_text
from .base import ApplyResult, Capabilities, Envelope, MailBackend, MessageRef, Page

FIXTURE_VERSION = 1


@dataclass
class FakeMessage:
    id: str
    folder: str
    uid: int
    raw: bytes
    labels: list[str] = field(default_factory=list)
    thread_id: str = ""
    date: str = "2026-09-01T08:00:00Z"

    def header(self, name: str) -> str:
        for line in self.raw.split(b"\r\n\r\n", 1)[0].replace(b"\r\n", b"\n").split(b"\n"):
            if line.lower().startswith(name.lower().encode() + b":"):
                return line.split(b":", 1)[1].strip().decode("utf-8", "replace")
        return ""


class FakeBackend(MailBackend):
    name = "fake"

    def __init__(self, fixture_path: str | Path, account: str = "fixture"):
        data = json.loads(Path(fixture_path).read_text())
        if data.get("fixture_version") != FIXTURE_VERSION:
            raise BackendError(
                f"fixture_version {data.get('fixture_version')} != {FIXTURE_VERSION}",
                code="fixture_version_mismatch",
            )
        self.account = account
        self.model = data.get("model", "folders")   # folders | labels
        self._identity = MailboxIdentity(
            backend="fake",
            provider_id=data["mailbox_id"],
            address=data.get("address", ""),
        )
        self.uidvalidity: int = data.get("uidvalidity", 1000)
        self._folders = [
            FolderInfo(
                id=f["id"],
                display_name=f["display_name"],
                path=f.get("path", f["display_name"]),
                delimiter=data.get("delimiter", "/"),
                special_use=frozenset(f.get("special_use", [])),
                namespace=f.get("namespace", "personal"),
                is_shared=f.get("is_shared", False),
                selectable=f.get("selectable", True),
                has_destructive_automation=f.get("has_destructive_automation", False),
                automation_note=f.get("automation_note", ""),
            )
            for f in data["folders"]
        ]
        self._labels = [
            LabelInfo(id=l["id"], display_name=l["display_name"], reserved=l.get("reserved", False))
            for l in data.get("labels", [])
        ]
        self.messages: dict[str, FakeMessage] = {}
        for m in data["messages"]:
            self.messages[m["id"]] = FakeMessage(
                id=m["id"],
                folder=m["folder"],
                uid=m["uid"],
                raw=m["raw"].encode("utf-8"),
                labels=list(m.get("labels", [])),
                thread_id=m.get("thread_id", m["id"]),
                date=m.get("date", "2026-09-01T08:00:00Z"),
            )
        self.caps = Capabilities(**data.get("capabilities", {}))
        #: test hook: reads never mutate, and the suite asserts this stays 0
        self.mutation_count = 0
        self.read_count = 0

    # ------------------------------------------------------------------ #
    def identity(self) -> MailboxIdentity:
        return self._identity

    def capabilities(self) -> Capabilities:
        return self.caps

    def list_folders(self) -> list[FolderInfo]:
        return list(self._folders)

    def list_labels(self) -> list[LabelInfo]:
        return list(self._labels)

    def _key(self, mid: str) -> str:
        return message_key(self._identity.key, "fake", mid)

    def _ref(self, m: FakeMessage) -> MessageRef:
        return MessageRef(
            account=self.account,
            message_id=m.id,
            folder_id=m.folder,
            message_key=self._key(m.id),
            uidvalidity=self.uidvalidity,
            uid=m.uid,
            thread_id=m.thread_id,
        )

    def _state(self, m: FakeMessage) -> MessageState:
        thread_size = sum(1 for x in self.messages.values() if x.thread_id == m.thread_id)
        mid = m.header("Message-ID") or None
        if self.model == "labels":
            return MessageState(
                backend="fake",
                label_ids=tuple(sorted(set(m.labels) | {m.folder})),
                rfc822_message_id=mid,
                thread_id=m.thread_id,
                thread_size=thread_size,
            )
        return MessageState(
            backend="fake",
            mailbox=m.folder,
            uidvalidity=self.uidvalidity,
            uid=m.uid,
            flags=tuple(sorted(m.labels)),
            rfc822_message_id=mid,
            thread_id=m.thread_id,
            thread_size=thread_size,
        )

    def list_messages(self, folder_id: str, cursor: str | None, limit: int) -> Page:
        self.read_count += 1
        if cursor:
            try:
                c = json.loads(cursor)
            except ValueError as exc:
                raise BackendError("malformed cursor", code="bad_cursor") from exc
            # Self-validating watermark.  An offset-based cursor over a folder the
            # agent is simultaneously emptying skips messages and repeats others.
            if c.get("f") != folder_id or c.get("v") != self.uidvalidity:
                return Page((), None, invalidated=True,
                            invalidation_reason="folder changed or UIDVALIDITY bumped")
            after = c.get("u", 0)
        else:
            after = 0
        msgs = sorted(
            (m for m in self.messages.values() if m.folder == folder_id and m.uid > after),
            key=lambda m: m.uid,
        )
        chunk = msgs[:limit]
        envs = []
        for m in chunk:
            subj, subj_flags = safe_header_text(m.header("Subject"))
            addr = safe_address(m.header("From"))
            envs.append(
                Envelope(
                    ref=self._ref(m),
                    date=m.date,
                    from_display=addr.display,
                    from_address=addr.addr,
                    from_domain=addr.addr.split("@")[-1] if "@" in addr.addr else "",
                    subject=subj,
                    size=len(m.raw),
                    unread="\\Seen" not in m.labels and "UNREAD" in m.labels + [m.folder]
                    or "\\Seen" not in m.labels,
                    has_attachments=b"Content-Disposition: attachment" in m.raw,
                    labels=tuple(sorted(m.labels)),
                    thread_size=sum(
                        1 for x in self.messages.values() if x.thread_id == m.thread_id
                    ),
                    flags=subj_flags,
                    display_name_spoof=addr.display_name_spoof,
                )
            )
        nxt = (
            json.dumps({"f": folder_id, "v": self.uidvalidity, "u": chunk[-1].uid},
                       separators=(",", ":"))
            if len(chunk) == limit and chunk
            else None
        )
        return Page(tuple(envs), nxt)

    def _resolve(self, ref: MessageRef) -> FakeMessage:
        m = self.messages.get(ref.message_id)
        if m is None:
            raise StaleHandle("message no longer exists at this handle", code="stale_handle")
        if ref.uidvalidity is not None and ref.uidvalidity != self.uidvalidity:
            raise StaleHandle(
                "UIDVALIDITY changed; the handle's UID may now refer to a different message",
                code="stale_handle",
            )
        if ref.uid is not None and m.uid != ref.uid:
            raise StaleHandle("UID no longer matches this message", code="stale_handle")
        if ref.message_key != self._key(m.id):
            raise StaleHandle("message key mismatch", code="stale_handle")
        return m

    def read_state(self, ref: MessageRef) -> MessageState:
        self.read_count += 1
        return self._state(self._resolve(ref))

    def fetch_raw(self, ref: MessageRef) -> bytes:
        self.read_count += 1
        m = self._resolve(ref)
        # A read must not change flags.  The suite asserts mutation_count stays 0
        # across every read path -- the IMAP \Seen trap in miniature.
        return m.raw

    def apply(self, ref: MessageRef, delta: StateDelta, precondition: MessageState) -> ApplyResult:
        m = self._resolve(ref)
        current = self._state(m)
        if current.state_hash() != precondition.state_hash():
            return ApplyResult("stale_handle", None, "state changed since it was read")
        if delta.to_folder is not None:
            if not (self.caps.atomic_move or self.caps.uidplus):
                # Refuse rather than COPY + \Deleted.  An extra copy is a
                # recoverable annoyance; a lost message is not.
                return ApplyResult(
                    "denied", current,
                    "server advertises neither UID MOVE nor UIDPLUS; refusing a non-atomic move",
                )
            if not self.caps.atomic_move:
                dupes = [
                    x for x in self.messages.values()
                    if x.folder == delta.to_folder
                    and x.header("Message-ID")
                    and x.header("Message-ID") == m.header("Message-ID")
                ]
                if dupes:
                    return ApplyResult(
                        "denied", current, "destination already holds this Message-ID"
                    )
                self.mutation_count += 1
                new_uid = max((x.uid for x in self.messages.values()), default=0) + 1
                copy = FakeMessage(
                    id=f"{m.id}-copy{new_uid}", folder=delta.to_folder, uid=new_uid,
                    raw=m.raw, labels=list(m.labels), thread_id=m.thread_id, date=m.date,
                )
                self.messages[copy.id] = copy
                return ApplyResult(
                    "copied_not_removed", self._state(m),
                    "copied; source left in place because the move could not be atomic",
                    dest_uid=new_uid,
                )
        self.mutation_count += 1
        new_state = apply_delta_to_state(current, delta)
        if self.model == "labels":
            m.labels = [l for l in new_state.label_ids if l != m.folder]
            if delta.to_folder:
                m.folder = delta.to_folder
                m.labels = [l for l in m.labels if l != m.folder]
        else:
            if delta.to_folder:
                m.folder = delta.to_folder
            m.labels = list(new_state.flags or ())
        return ApplyResult("applied", self._state(m), new_message_id=m.id)

    # ---------------- test hooks ----------------
    def bump_uidvalidity(self) -> None:
        self.uidvalidity += 1

    def rename_label(self, label_id: str, new_name: str) -> None:
        self._labels = [
            LabelInfo(id=l.id, display_name=new_name if l.id == label_id else l.display_name,
                      reserved=l.reserved)
            for l in self._labels
        ]
