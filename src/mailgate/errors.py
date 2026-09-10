"""Status codes and exceptions.

The status enum is deliberately wide.  A review finding: an outcome that cannot be
named gets reported as ``applied`` or as a generic error, and the agent's retry
behaviour is then undefined -- the fast path to duplicated mail.  Every status
below carries an explicit retry contract, and ``RETRY_CONTRACT`` is the single
source of truth quoted by both the tool responses and SKILL.md.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import enum


class Status(str, enum.Enum):
    APPLIED = "applied"
    DRY_RUN = "dry_run"
    PENDING_APPROVAL = "pending_approval"
    DENIED = "denied"
    DUPLICATE_IGNORED = "duplicate_ignored"
    IDEMPOTENCY_KEY_REUSE = "idempotency_key_reuse"
    STALE_HANDLE = "stale_handle"
    CURSOR_INVALIDATED = "cursor_invalidated"
    PARTIALLY_APPLIED = "partially_applied"
    COPIED_NOT_REMOVED = "copied_not_removed"
    UNKNOWN_OUTCOME = "unknown_outcome"
    ACCOUNT_BUSY = "account_busy"
    RATE_LIMITED = "rate_limited"


#: retry / do-not-retry / escalate, per status.  Handed to the agent verbatim.
RETRY_CONTRACT: dict[str, str] = {
    Status.APPLIED: "do-not-retry: the change is done.",
    Status.DRY_RUN: "do-not-retry: validated only, nothing was sent to the provider.",
    Status.PENDING_APPROVAL: (
        "do-not-retry-as-new: re-call with the SAME idempotency_key to poll status. "
        "Polls are capped; a new key creates a second approval prompt and will be auto-denied."
    ),
    Status.DENIED: "do-not-retry: policy refused this. Report the reason, do not rephrase and resubmit.",
    Status.DUPLICATE_IGNORED: "do-not-retry: this exact request already reached a terminal state (see original_status).",
    Status.IDEMPOTENCY_KEY_REUSE: "do-not-retry: bug in the caller. Use a fresh key per distinct action.",
    Status.STALE_HANDLE: "retry-once after re-reading the message; the mailbox changed underneath.",
    Status.CURSOR_INVALIDATED: "retry from the start of the folder; do not report the folder as fully triaged.",
    Status.PARTIALLY_APPLIED: "escalate: tell the human which labels applied and which did not.",
    Status.COPIED_NOT_REMOVED: "escalate: a duplicate now exists and needs manual reconciliation.",
    Status.UNKNOWN_OUTCOME: "escalate: NEVER retry. A human must resolve this with `mailgate reconcile`.",
    Status.ACCOUNT_BUSY: "retry-later: another writer holds the account lock.",
    Status.RATE_LIMITED: "do-not-retry this run: the budget is exhausted. Stop and report.",
}


class MailgateError(Exception):
    """Base class.  Carries a stable code; never a provider payload."""

    code = "internal_error"

    def __init__(self, message: str, code: str | None = None, **detail):
        super().__init__(message)
        if code:
            self.code = code
        self.detail = detail


class ConfigError(MailgateError):
    code = "config_error"


class PolicyDenied(MailgateError):
    code = "policy_denied"


class StaleHandle(MailgateError):
    code = "stale_handle"


class BackendError(MailgateError):
    """Raised instead of letting a provider response reach the agent.

    Provider bodies can contain tokens and internal headers, so adapters must
    translate rather than propagate.
    """

    code = "backend_error"


class UnknownOutcome(MailgateError):
    """The provider may or may not have applied the change.  Never retried automatically."""

    code = "unknown_outcome"
