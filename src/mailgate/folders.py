"""Folder / label model shared by every backend.

The single most important field here is ``special_use``: destination safety is
decided by the *provider's own attribute*, never by the display name.  A folder
called ``Archive-2024`` may carry ``\\Trash``; a folder called ``Trash`` may be an
ordinary mailbox.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from dataclasses import dataclass, field

#: Attributes that make a folder unusable as a mutation destination.
#: RFC 6154 special-use, plus Gmail reserved label ids and Graph wellKnownFolderNames
#: mapped onto the same vocabulary by each adapter.
DESTRUCTIVE_ATTRS = frozenset(
    {
        r"\Trash",       # deletion
        r"\Junk",        # effectively deletion; also trains the spam filter
        r"\Drafts",      # a draft is a send-adjacent object
        r"\Sent",
        r"\Outbox",      # on an MTA-watched Maildir this is a send primitive
        r"\Queue",
        r"\All",         # Gmail "All Mail": a move here is an archive-and-hide
        r"\Deleted",
        r"\Recoverable", # Graph recoverableitemsdeletions
    }
)

#: Provider-reserved label/flag ids the agent may never add or remove.
#: `remove` is the hide-mail verb: removing INBOX archives, removing UNREAD marks
#: read, removing STARRED/IMPORTANT destroys the human's own triage state.
RESERVED_LABEL_IDS = frozenset(
    {
        # Gmail
        "INBOX", "UNREAD", "STARRED", "IMPORTANT", "SENT", "DRAFT", "TRASH", "SPAM",
        "CHAT", "CATEGORY_PERSONAL", "CATEGORY_SOCIAL", "CATEGORY_PROMOTIONS",
        "CATEGORY_UPDATES", "CATEGORY_FORUMS",
        # IMAP system flags
        r"\Seen", r"\Answered", r"\Flagged", r"\Deleted", r"\Draft", r"\Recent",
        # Graph pseudo-properties an adapter must never expose as a "label"
        "isRead", "flag", "inferenceClassification",
    }
)

RESERVED_PREFIXES = ("CATEGORY_",)


def is_reserved_label(label_id: str) -> bool:
    if label_id in RESERVED_LABEL_IDS:
        return True
    return any(label_id.startswith(p) for p in RESERVED_PREFIXES)


@dataclass(frozen=True)
class FolderInfo:
    id: str                       # provider id; for IMAP the mailbox name
    display_name: str
    path: str                     # server-delimited full path
    delimiter: str                # from the server (LIST), never assumed to be "/"
    special_use: frozenset[str] = frozenset()
    namespace: str = "personal"   # personal | other_users | shared
    is_shared: bool = False
    selectable: bool = True
    #: True when the adapter found a server-side rule or retention policy that acts
    #: on this folder.  A destination with a delete/forward rule is deferred deletion.
    has_destructive_automation: bool = False
    automation_note: str = ""

    @property
    def is_destructive(self) -> bool:
        return bool(self.special_use & DESTRUCTIVE_ATTRS)

    @property
    def is_outside_personal(self) -> bool:
        return self.is_shared or self.namespace != "personal"


@dataclass(frozen=True)
class LabelInfo:
    id: str
    display_name: str
    reserved: bool = False


@dataclass(frozen=True)
class MailboxIdentity:
    """Resolved identity of the actual mailbox behind a config alias.

    Locks, budgets and the same-account check key on THIS, not on the alias --
    otherwise a Gmail account also configured over IMAP doubles every budget and
    two adapters race the same folder.
    """

    backend: str
    provider_id: str      # Graph mailbox GUID / Gmail emailAddress / host+authzid
    address: str = ""

    @property
    def key(self) -> str:
        return f"{self.backend}:{self.provider_id}"
