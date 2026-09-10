"""Gmail adapter -- WRITTEN, NOT YET EXERCISED AGAINST A REAL ACCOUNT.

**The scope situation, verified September 2026, and it is bad.**

``users.messages.modify`` -- the only way to label or "move" a Gmail message --
accepts only ``https://mail.google.com/``, ``gmail.modify``, and an apparently
undocumented ``gmail.modify.restricted``.  ``gmail.labels`` alone cannot label a
*message*.  And ``gmail.modify`` is described by Google as "Read, compose, and
**send** emails", excluding only *permanent* deletion -- trashing is still allowed.

So on the documented path, the token mailgate needs in order to file mail can also
send mail and can also trash mail.  Neither restriction is expressible as a scope.
``AUTH_SCOPES`` below therefore tries the restricted variant first and records what
was actually granted; the ``.restricted`` scope is ``[low confidence]`` -- it
appears in the method reference but not in the scopes overview.

**Consequence, stated plainly:** for Gmail, "no send, no delete" is enforced by
this adapter's code, by the request chokepoint in httpgate.py, and by confining the
credential -- not by the provider.  Mitigations in docs/HARDENING.md: a dedicated
Google Cloud project with only the Gmail API enabled, consent restricted to
Spencer's own account, and the refresh token held in his secret manager.

Gmail-specific traps:

* A "move" is label surgery.  It is ONE hardcoded shape -- ``addLabelIds:[dest]``,
  ``removeLabelIds:["INBOX"]`` -- and that is the only path in mailgate permitted
  to touch INBOX.
* ``addLabelIds:["TRASH"]`` **is** deletion, and ``["SPAM"]`` effectively is.  Both
  are on the reserved denylist, and the destination check is by label id.
* Labelling one message makes the whole conversation appear under that label in the
  UI.  So thread size is captured, shown in the approval prompt, and charged to the
  budget.  ``threads.modify`` is never called.
* ``format=metadata`` returns a ``snippet`` of body text; it is dropped, because
  otherwise attacker-authored content reaches the agent through the envelope path
  without passing the sanitiser.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from ..errors import BackendError
from .base import ApplyResult, Capabilities, MailBackend, MessageRef, Page

AUTH_SCOPES_PREFERRED = ("https://www.googleapis.com/auth/gmail.modify.restricted",)
AUTH_SCOPES_FALLBACK = ("https://www.googleapis.com/auth/gmail.modify",)

#: Label ids that may never appear in addLabelIds or removeLabelIds, with the one
#: exception of INBOX in removeLabelIds during move_message.
FORBIDDEN_LABEL_IDS = frozenset({"TRASH", "SPAM", "DRAFT", "SENT", "CHAT"})


def build_modify_body(add_ids: tuple[str, ...], remove_ids: tuple[str, ...],
                      *, allow_inbox_removal: bool) -> dict:
    """The single place a modify body is constructed.  Refuses anything else."""
    for lid in add_ids:
        if lid in FORBIDDEN_LABEL_IDS or lid == "INBOX":
            raise BackendError(f"addLabelIds may not contain {lid}", code="forbidden_label")
    for lid in remove_ids:
        if lid in FORBIDDEN_LABEL_IDS:
            raise BackendError(f"removeLabelIds may not contain {lid}", code="forbidden_label")
        if lid == "INBOX" and not allow_inbox_removal:
            raise BackendError(
                "removing INBOX is permitted only as part of move_message",
                code="forbidden_label",
            )
    return {"addLabelIds": list(add_ids), "removeLabelIds": list(remove_ids)}


class GmailBackend(MailBackend):
    name = "gmail"

    def __init__(self, account):
        raise BackendError(
            "the Gmail adapter is not enabled. It has never been run against a real account and "
            "Spencer has not approved live testing. Read the scope discussion at the top of this "
            "module first: the token this adapter needs is send-capable on the documented path.",
            code="adapter_not_approved",
        )

    def identity(self):
        """``GET /gmail/v1/users/me/profile`` -> emailAddress is the mailbox identity."""
        raise NotImplementedError

    def capabilities(self) -> Capabilities:
        return Capabilities(atomic_move=True, uidplus=True, labels=True, folders=False,
                            conditional_write=False)

    def list_folders(self):
        """Labels presented as folders.  Reserved ids carry synthetic special-use so
        the shared destination checks work unchanged: TRASH -> \\Trash, SPAM ->
        \\Junk, DRAFT -> \\Drafts, SENT -> \\Sent, and Gmail's "All Mail" -> \\All.

        Startup also reads ``settings/filters``, ``settings/autoForwarding`` and
        ``settings/forwardingAddresses``; any filter with a delete or forward action
        targeting an allowlisted destination marks that destination as carrying
        destructive automation, and mailgate then refuses to start.
        """
        raise NotImplementedError

    def list_labels(self):
        raise NotImplementedError

    def list_messages(self, folder_id: str, cursor: str | None, limit: int) -> Page:
        """``GET messages?labelIds=<id>&pageToken=...`` then a metadata get per id.

        The cursor carries the ``historyId`` observed at listing start; a
        discontinuity invalidates it rather than silently resuming.  ``snippet`` is
        discarded.
        """
        raise NotImplementedError

    def read_state(self, ref: MessageRef):
        """``GET messages/<id>?format=metadata&metadataHeaders=Message-ID`` -- the
        full raw ``labelIds`` array is the state, and the Message-ID is re-confirmed
        against the handle before any mutation."""
        raise NotImplementedError

    def fetch_raw(self, ref: MessageRef) -> bytes:
        """``GET messages/<id>?format=raw``.  Does not change read state."""
        raise NotImplementedError

    def apply(self, ref: MessageRef, delta, precondition) -> ApplyResult:
        """``POST messages/<id>/modify`` with the body from build_modify_body.

        Gmail applies add and remove atomically, so there is no partial-application
        case here.  There is no ETag: the compare-and-set is a re-read of labelIds
        immediately before the call, and the post-state is read back after.
        """
        raise NotImplementedError
