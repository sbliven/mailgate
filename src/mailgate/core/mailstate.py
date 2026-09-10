"""The canonical state serializer -- built first, on purpose.

Five paths need byte-identical state: the read path, the approval precondition
hash, the audit ``prior``/``post`` records, the pre-mutation compare-and-set, and
undo's precondition check.  Without one serializer, label sets returned in
arbitrary order make the TOCTOU check fail every time: a liveness bug that looks
exactly like a working safety feature, because every mutation gets refused and
re-queued.

The state schema is a provider-tagged union.  A folder-shaped schema
(``{folder, labels}``) cannot represent Gmail, where state IS the complete label-id
set and a "move" is an add/remove pair -- undoing from a folder-shaped record would
restore INBOX and silently drop every other label the message carried.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from typing import Literal

STATE_VERSION = 1

Backend = Literal["gmail", "graph", "imap", "fake"]


def canonical_json(obj) -> bytes:
    """One canonicalisation, versioned, frozen by golden-file tests.

    ensure_ascii keeps the bytes stable across Python Unicode changes;
    sort_keys and the tight separators keep them stable across dict ordering.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class MessageState:
    """Complete, provider-native state of one message.

    Every provider-specific field is preserved verbatim so that undo can reverse a
    *delta* rather than restore a snapshot.  Snapshot restore would clobber edits
    Spencer made in his own mail client between the mutation and the undo.
    """

    backend: Backend
    version: int = STATE_VERSION

    # --- gmail ---------------------------------------------------------------
    # the FULL raw labelIds array as returned, not just the allowlisted subset
    label_ids: tuple[str, ...] | None = None

    # --- graph ---------------------------------------------------------------
    parent_folder_id: str | None = None      # immutable id
    categories: tuple[str, ...] | None = None
    is_read: bool | None = None
    is_flagged: bool | None = None
    etag: str | None = None                  # Graph's conditional-write primitive

    # --- imap ----------------------------------------------------------------
    mailbox: str | None = None
    uidvalidity: int | None = None
    uid: int | None = None
    modseq: int | None = None                # CONDSTORE compare-and-set
    flags: tuple[str, ...] | None = None     # system flags + keywords

    # --- common --------------------------------------------------------------
    # advisory only: RFC822 Message-ID is optional, duplicated and sender-controlled,
    # so it must never drive an identity decision.  Explicitly None when absent.
    rfc822_message_id: str | None = None
    thread_id: str | None = None
    thread_size: int | None = None

    def canonical(self) -> dict:
        """Sorted, provider-tagged dict.

        ``etag`` and ``modseq`` are excluded from the *hash* below but kept in the
        dict for the audit record: they change on every unrelated write, so
        including them in the precondition hash would make every mutation stale.
        """
        d: dict = {"v": self.version, "backend": self.backend}
        if self.label_ids is not None:
            d["label_ids"] = sorted(self.label_ids)
        if self.parent_folder_id is not None:
            d["parent_folder_id"] = self.parent_folder_id
        if self.categories is not None:
            d["categories"] = sorted(self.categories)
        if self.is_read is not None:
            d["is_read"] = self.is_read
        if self.is_flagged is not None:
            d["is_flagged"] = self.is_flagged
        if self.mailbox is not None:
            d["mailbox"] = self.mailbox
        if self.uidvalidity is not None:
            d["uidvalidity"] = self.uidvalidity
        if self.uid is not None:
            d["uid"] = self.uid
        if self.flags is not None:
            d["flags"] = sorted(self.flags)
        if self.rfc822_message_id is not None:
            d["rfc822_message_id"] = self.rfc822_message_id
        if self.thread_id is not None:
            d["thread_id"] = self.thread_id
        return d

    def record(self) -> dict:
        """Canonical dict plus the volatile concurrency tokens, for the audit log."""
        d = self.canonical()
        if self.etag is not None:
            d["etag"] = self.etag
        if self.modseq is not None:
            d["modseq"] = self.modseq
        if self.thread_size is not None:
            d["thread_size"] = self.thread_size
        return d

    def state_hash(self) -> str:
        return sha256_hex(canonical_json(self.canonical()))


@dataclass(frozen=True)
class StateDelta:
    """A reversible change, expressed in provider-native terms.

    Deltas -- not snapshots -- are what get applied and what get inverted.
    """

    add_labels: tuple[str, ...] = ()
    remove_labels: tuple[str, ...] = ()
    to_folder: str | None = None            # provider folder/mailbox id
    from_folder: str | None = None          # recorded so inverse() is exact
    add_categories: tuple[str, ...] = ()
    remove_categories: tuple[str, ...] = ()
    add_flags: tuple[str, ...] = ()
    remove_flags: tuple[str, ...] = ()

    def is_empty(self) -> bool:
        return not any(
            (
                self.add_labels,
                self.remove_labels,
                self.to_folder,
                self.add_categories,
                self.remove_categories,
                self.add_flags,
                self.remove_flags,
            )
        )

    def inverse(self) -> "StateDelta":
        """The undo delta.  Requires from_folder to have been captured."""
        return StateDelta(
            add_labels=self.remove_labels,
            remove_labels=self.add_labels,
            to_folder=self.from_folder,
            from_folder=self.to_folder,
            add_categories=self.remove_categories,
            remove_categories=self.add_categories,
            add_flags=self.remove_flags,
            remove_flags=self.add_flags,
        )

    def canonical(self) -> dict:
        d = {}
        for k in (
            "add_labels",
            "remove_labels",
            "add_categories",
            "remove_categories",
            "add_flags",
            "remove_flags",
        ):
            v = getattr(self, k)
            if v:
                d[k] = sorted(v)
        if self.to_folder is not None:
            d["to_folder"] = self.to_folder
        if self.from_folder is not None:
            d["from_folder"] = self.from_folder
        return d

    def touched_labels(self) -> set[str]:
        return set(self.add_labels) | set(self.remove_labels)


def apply_delta_to_state(state: MessageState, delta: StateDelta) -> MessageState:
    """Pure, in-memory application -- used by the fake backend and by tests to
    assert that inverse() really round-trips."""
    kw = {}
    if state.label_ids is not None:
        labels = set(state.label_ids) | set(delta.add_labels)
        labels -= set(delta.remove_labels)
        kw["label_ids"] = tuple(sorted(labels))
    if delta.to_folder is not None:
        if state.parent_folder_id is not None:
            kw["parent_folder_id"] = delta.to_folder
        if state.mailbox is not None:
            kw["mailbox"] = delta.to_folder
    if state.categories is not None:
        cats = set(state.categories) | set(delta.add_categories)
        cats -= set(delta.remove_categories)
        kw["categories"] = tuple(sorted(cats))
    if state.flags is not None:
        fl = set(state.flags) | set(delta.add_flags)
        fl -= set(delta.remove_flags)
        kw["flags"] = tuple(sorted(fl))
    return replace(state, **kw)


def message_key(account_identity: str, backend: str, immutable_id: str) -> str:
    """The one true message identity.

    Keyed on the provider's immutable id, NOT on the RFC822 Message-ID, which is
    optional, frequently duplicated (list mail delivered twice; the same message in
    Inbox and All Mail) and entirely sender-controlled.
    """
    return sha256_hex(
        canonical_json({"a": account_identity, "b": backend, "i": immutable_id})
    )
