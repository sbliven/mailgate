"""Backend interface.

Deliberate omissions, enforced by the ABC rather than by convention: there is no
``delete``, no ``expunge``, no ``send``, no ``create_folder``, no ``create_label``
and no raw passthrough.  A backend cannot offer what the interface does not name,
and ``tests/test_no_forbidden_verbs.py`` greps the adapters as a regression lint --
a lint, not a boundary, which is why the real control is the request chokepoint in
each adapter.

``fetch_raw`` MUST be non-mutating.  On IMAP that means ``EXAMINE`` and
``BODY.PEEK[]``: plain ``FETCH BODY[]`` sets ``\\Seen`` and ``SELECT`` clears
``\\Recent``, which would make a "read" tool silently mark the whole inbox read --
mail hidden, with no approval and no audit record.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import abc
import base64
import json
from dataclasses import dataclass, field

from ..core.mailstate import MessageState, StateDelta, message_key, sha256_hex
from ..errors import BackendError, StaleHandle
from ..folders import FolderInfo, LabelInfo, MailboxIdentity


@dataclass(frozen=True)
class MessageRef:
    """Opaque handle handed to the agent and echoed back.

    Carries the provider's immutable id plus the IMAP coordinates needed to detect
    that the mailbox moved underneath us.
    """

    account: str
    message_id: str          # immutable provider id
    folder_id: str
    message_key: str
    uidvalidity: int | None = None
    uid: int | None = None
    thread_id: str | None = None

    def token(self) -> str:
        payload = {
            "a": self.account,
            "i": self.message_id,
            "f": self.folder_id,
            "k": self.message_key,
            "v": self.uidvalidity,
            "u": self.uid,
            "t": self.thread_id,
        }
        return base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()

    @staticmethod
    def parse(token: str) -> "MessageRef":
        try:
            d = json.loads(base64.urlsafe_b64decode(token.encode()))
            return MessageRef(
                account=d["a"], message_id=d["i"], folder_id=d["f"], message_key=d["k"],
                uidvalidity=d.get("v"), uid=d.get("u"), thread_id=d.get("t"),
            )
        except Exception as exc:  # noqa: BLE001
            raise BackendError("malformed message handle", code="bad_handle") from exc


@dataclass(frozen=True)
class Envelope:
    ref: MessageRef
    date: str
    from_display: str
    from_address: str
    from_domain: str
    subject: str
    size: int
    unread: bool
    has_attachments: bool
    labels: tuple[str, ...] = ()
    thread_size: int = 1
    flags: dict = field(default_factory=dict)
    display_name_spoof: bool = False


@dataclass(frozen=True)
class Page:
    envelopes: tuple[Envelope, ...]
    next_cursor: str | None
    invalidated: bool = False
    invalidation_reason: str = ""


@dataclass(frozen=True)
class ApplyResult:
    status: str
    post_state: MessageState | None
    note: str = ""
    dest_uid: int | None = None
    new_message_id: str | None = None
    per_label: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Capabilities:
    #: RFC 6851 UID MOVE.  Without it (and without UIDPLUS COPYUID) mailgate will
    #: not attempt a move at all rather than emit \Deleted to finish a COPY.
    atomic_move: bool = True
    uidplus: bool = True
    condstore: bool = False
    labels: bool = False          # Gmail-style label model
    folders: bool = True
    conditional_write: bool = False   # ETag / MODSEQ compare-and-set


class MailBackend(abc.ABC):
    name: str = "abstract"

    @abc.abstractmethod
    def identity(self) -> MailboxIdentity: ...

    @abc.abstractmethod
    def capabilities(self) -> Capabilities: ...

    @abc.abstractmethod
    def list_folders(self) -> list[FolderInfo]: ...

    @abc.abstractmethod
    def list_labels(self) -> list[LabelInfo]: ...

    @abc.abstractmethod
    def list_messages(self, folder_id: str, cursor: str | None, limit: int) -> Page: ...

    @abc.abstractmethod
    def read_state(self, ref: MessageRef) -> MessageState:
        """Current state, and the pre-mutation identity confirmation.

        Implementations MUST raise StaleHandle if the message that now occupies the
        handle's coordinates is not the same message -- UIDVALIDITY change, UID
        reuse, or a Message-ID that no longer matches.
        """

    @abc.abstractmethod
    def fetch_raw(self, ref: MessageRef) -> bytes:
        """Non-mutating fetch of the full RFC822 message."""

    @abc.abstractmethod
    def apply(self, ref: MessageRef, delta: StateDelta, precondition: MessageState) -> ApplyResult:
        """Apply a delta under a compare-and-set on ``precondition``."""

    def close(self) -> None:  # pragma: no cover - adapters override as needed
        return None
