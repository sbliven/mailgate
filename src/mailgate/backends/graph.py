"""Microsoft 365 / Graph adapter -- WRITTEN, NOT YET EXERCISED AGAINST A REAL TENANT.

**Scope situation, verified September 2026:** withholding ``Mail.Send`` makes
sending impossible at the token level -- genuinely better than Gmail.  But
``Mail.ReadWrite`` is the only permission that allows move/categorise and it also
allows delete, so delete-prevention is application-level here too.  Requested:
``Mail.ReadWrite`` + ``MailboxFolder.Read``, never ``Mail.ReadWrite.All``, never
``Mail.Send``.

Graph-specific traps this adapter exists to avoid:

* **Message ids change on move.**  ``POST /messages/{id}/move`` returns a new
  resource with a new id, so an audit record written with the pre-move id points at
  nothing and undo cannot address the message.  Every request therefore sends
  ``Prefer: IdType="ImmutableId"``, the adapter refuses to run if the mailbox does
  not honour it, and the post-move id is recorded and aliased.
* **``categories`` is a PATCH of the whole array.**  Read-modify-write, so a
  category Spencer added in Outlook between the read and the PATCH is silently
  erased.  Every PATCH carries ``If-Match: <etag>`` and retries the
  read-modify-write on 412.  That ETag is the correct implementation of the
  precondition hash on this backend.
* **``destinationId: deleteditems``** (or ``recoverableitemsdeletions``,
  ``junkemail``) is deletion by move.  Well-known folder names are mapped onto
  special-use attributes so the core's destructive-destination check catches them,
  and DELETE is not on the request allowlist at all.
* **``bodyPreview`` and ``uniqueBody``** arrive in list responses unless excluded,
  which would put attacker-authored body text past the sanitiser.  Every list uses
  an explicit ``$select`` that omits them.
* **``$skip`` paging** over a folder being emptied skips messages.  Paging uses a
  ``(receivedDateTime, immutable id)`` watermark with a stable ``$orderby``.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from ..errors import BackendError
from .base import ApplyResult, Capabilities, MailBackend, MessageRef, Page

DELEGATED_SCOPES = ("Mail.ReadWrite", "MailboxFolder.Read", "offline_access")
#: Never requested.  Listed so a reviewer can see the omission is deliberate.
NEVER_REQUESTED = ("Mail.Send", "Mail.ReadWrite.All", "Mail.ReadWrite.Shared")

PREFER_HEADERS = {"Prefer": 'IdType="ImmutableId", outlook.body-content-type="text"'}

ENVELOPE_SELECT = ",".join(
    [
        "id", "internetMessageId", "conversationId", "receivedDateTime", "subject", "from",
        "hasAttachments", "isRead", "flag", "categories", "parentFolderId",
        # bodyPreview and uniqueBody are deliberately absent
    ]
)

WELLKNOWN_TO_SPECIAL_USE = {
    "deleteditems": r"\Trash",
    "recoverableitemsdeletions": r"\Recoverable",
    "junkemail": r"\Junk",
    "drafts": r"\Drafts",
    "sentitems": r"\Sent",
    "outbox": r"\Outbox",
    "archive": r"\Archive",
}


class GraphBackend(MailBackend):
    name = "graph"

    def __init__(self, account):
        raise BackendError(
            "the Microsoft Graph adapter is not enabled. It has never been run against a real "
            "tenant and Spencer has not approved live testing. Enable it deliberately: "
            "live=true, --enable-live-providers, and mode=dry_run against a throwaway mailbox "
            "first.",
            code="adapter_not_approved",
        )

    def identity(self):
        """``GET /v1.0/me`` -> the mailbox GUID is the identity, not the alias."""
        raise NotImplementedError

    def capabilities(self) -> Capabilities:
        return Capabilities(atomic_move=True, uidplus=True, folders=True, labels=False,
                            conditional_write=True)

    def list_folders(self):
        """``GET /me/mailFolders?$top=...`` recursively, mapping wellKnownFolderName
        onto special-use.  ``GET /me/mailFolders/inbox/messageRules`` is read at
        startup: any rule with a delete, forward or redirect action that references
        an allowlisted destination marks it as carrying destructive automation, and
        mailgate refuses to start."""
        raise NotImplementedError

    def list_labels(self):
        """``GET /me/outlook/masterCategories``.

        Graph accepts arbitrary strings in ``categories`` and never validates them,
        so a gap in the allowlist would write attacker-chosen text into the mailbox
        -- a covert channel and a persistence mechanism.  Only ids from the master
        list are ever sent."""
        raise NotImplementedError

    def list_messages(self, folder_id: str, cursor: str | None, limit: int) -> Page:
        raise NotImplementedError

    def read_state(self, ref: MessageRef):
        """``GET /me/messages/{immutable-id}?$select=...`` and re-confirm
        ``internetMessageId`` against the handle."""
        raise NotImplementedError

    def fetch_raw(self, ref: MessageRef) -> bytes:
        """``GET /me/messages/{id}/$value``.  Reading does not change ``isRead``."""
        raise NotImplementedError

    def apply(self, ref: MessageRef, delta, precondition) -> ApplyResult:
        """Categories: ``PATCH /me/messages/{id}`` with ``If-Match``.
        Move: ``POST /me/messages/{id}/move`` -- record the returned id."""
        raise NotImplementedError
