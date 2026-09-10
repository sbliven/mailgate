"""IMAP adapter -- WRITTEN, NOT YET EXERCISED AGAINST A REAL SERVER.

Requires ``live = true`` in the policy AND ``--enable-live-providers`` on the
command line.  Spencer has not approved live testing, so this module raises on
construction unless both are set.

The IMAP-specific traps this adapter exists to avoid:

* **Reads must not mutate.**  ``SELECT`` clears ``\\Recent`` and ``FETCH BODY[]``
  sets ``\\Seen``.  Every read path here uses ``EXAMINE`` and ``BODY.PEEK[]``.  A
  read that marked mail seen would hide it with no approval and no audit record.
* **A UID is meaningful only within (mailbox, UIDVALIDITY)**, and some servers
  reuse UIDs inside one UIDVALIDITY in violation of RFC 3501.  So every mutation
  re-confirms the RFC822 Message-ID before acting, and refuses on mismatch.
* **Never emit ``STORE +FLAGS (\\Deleted)`` and never ``EXPUNGE``.**  A move uses
  RFC 6851 ``UID MOVE``; where that is unavailable, ``UID COPY`` + UIDPLUS
  ``COPYUID`` and then a deliberate stop, reporting ``copied_not_removed``.  Where
  neither is advertised the move is refused outright: unbounded duplicates can
  fill a quota, and a full mailbox bounces inbound mail -- destruction achieved
  with allowlisted moves only.
* **No SMTP.**  ``smtplib`` is never imported.  An IMAP app password usually also
  unlocks SMTP, so the credential is send-capable even though this code is not --
  which is why the credential is confined, per docs/HARDENING.md.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from ..errors import BackendError
from .base import ApplyResult, Capabilities, MailBackend, MessageRef, Page

#: Commands this adapter is permitted to transmit.  Checked at the point of
#: transmission, so a constructed string cannot smuggle a verb past it.
ALLOWED_COMMANDS = frozenset(
    {
        "CAPABILITY", "AUTHENTICATE", "LOGIN", "LOGOUT", "NAMESPACE", "LIST", "LSUB",
        "EXAMINE",           # never SELECT: SELECT clears \Recent
        "STATUS", "SEARCH", "UID", "FETCH", "NOOP", "ID", "ENABLE", "GETACL", "MYRIGHTS",
    }
)
FORBIDDEN_COMMANDS = frozenset({"EXPUNGE", "CLOSE", "DELETE", "RENAME", "CREATE", "SETACL",
                                "APPEND", "SELECT", "SUBSCRIBE", "UNSUBSCRIBE"})
#: UID subcommands.  STORE is permitted only for keyword changes, and the flag
#: allowlist below is what makes that safe.
ALLOWED_UID_SUBCOMMANDS = frozenset({"FETCH", "SEARCH", "MOVE", "COPY", "STORE"})
FORBIDDEN_FLAGS = frozenset({r"\Deleted", r"\Seen", r"\Answered", r"\Draft", r"\Recent"})


def check_command(command: str, *, flags: tuple[str, ...] = ()) -> None:
    verb = command.strip().split()[0].upper() if command.strip() else ""
    if verb in FORBIDDEN_COMMANDS or verb not in ALLOWED_COMMANDS:
        raise BackendError(f"IMAP command {verb!r} is not permitted by mailgate",
                           code="imap_command_blocked")
    if verb == "UID":
        parts = command.strip().split()
        sub = parts[1].upper() if len(parts) > 1 else ""
        if sub not in ALLOWED_UID_SUBCOMMANDS:
            raise BackendError(f"UID {sub} is not permitted", code="imap_command_blocked")
    if verb == "FETCH" or (verb == "UID" and "FETCH" in command.upper()):
        up = command.upper()
        if "BODY[" in up and "BODY.PEEK[" not in up:
            raise BackendError(
                "FETCH BODY[ without .PEEK sets \\Seen; use BODY.PEEK[",
                code="mutating_read_blocked",
            )
    for f in flags:
        if f in FORBIDDEN_FLAGS:
            raise BackendError(f"flag {f} may not be set or cleared", code="imap_flag_blocked")


class ImapBackend(MailBackend):
    name = "imap"

    def __init__(self, account):
        raise BackendError(
            "the IMAP adapter is not enabled. It has never been run against a real server and "
            "Spencer has not approved live testing. Enable it deliberately: set live=true for "
            "this account, pass --enable-live-providers, and start with mode=dry_run against a "
            "throwaway account.",
            code="adapter_not_approved",
        )

    # The method bodies below document the exact command shapes this adapter will
    # use, so they can be reviewed before anything touches a real server.
    def identity(self):
        """``ID``/``NAMESPACE``; identity = host + authenticated username."""
        raise NotImplementedError

    def capabilities(self) -> Capabilities:
        """From ``CAPABILITY``: MOVE (RFC 6851), UIDPLUS (RFC 4315), CONDSTORE."""
        raise NotImplementedError

    def list_folders(self):
        """``LIST "" "*" RETURN (SPECIAL-USE)`` plus ``NAMESPACE``.

        The delimiter comes from LIST -- it is not assumed to be "/".  Folders
        outside the personal namespace, and anything MYRIGHTS/GETACL shows as
        reachable by another principal, are marked shared and can never be a
        destination.
        """
        raise NotImplementedError

    def list_labels(self):
        """IMAP keywords, from the PERMANENTFLAGS of an EXAMINE."""
        raise NotImplementedError

    def list_messages(self, folder_id: str, cursor: str | None, limit: int) -> Page:
        """``EXAMINE`` then ``UID FETCH <last+1>:* (UID ENVELOPE RFC822.SIZE FLAGS
        BODYSTRUCTURE BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])``.

        Cursor = ``(mailbox, UIDVALIDITY, last_UID)``, self-validating: an
        offset-based cursor over a folder being emptied skips messages silently.
        """
        raise NotImplementedError

    def read_state(self, ref: MessageRef):
        """``EXAMINE``, compare UIDVALIDITY, then
        ``UID FETCH <uid> (FLAGS MODSEQ BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])``
        and refuse unless the Message-ID still matches the handle."""
        raise NotImplementedError

    def fetch_raw(self, ref: MessageRef) -> bytes:
        """``UID FETCH <uid> BODY.PEEK[]`` -- PEEK, always."""
        raise NotImplementedError

    def apply(self, ref: MessageRef, delta, precondition) -> ApplyResult:
        """Keywords: one ``UID STORE`` carrying every keyword, with
        ``(UNCHANGEDSINCE <modseq>)`` where CONDSTORE is advertised -- a real
        compare-and-set.  Several STOREs can partially apply while the audit record
        claims success.

        Move: ``UID MOVE`` if advertised; else ``UID COPY`` + ``COPYUID`` and stop
        with ``copied_not_removed``; else refuse.
        """
        raise NotImplementedError
