"""Out-of-band approval, where the broker itself executes the mutation.

The first design handed the agent a capability token and let it redeem the
mutation later.  That created a replay surface *and* a worse failure: Spencer
approves at t=100 s, the agent re-calls at t=310 s, the token has expired, and he
believes he approved a move that never happened.

So: the broker owns the pending queue and a worker.  The moment Spencer accepts,
the broker performs the mutation, under the account lock, and records the outcome.
The agent's re-call is a side-effect-free status read.  No token ever leaves the
process; there is nothing to replay.

Everything rendered to Spencer is stripped of ANSI, control and bidi characters
and hard-truncated, and the account / operation / from -> to line is built from
server-resolved ids in a fixed region no untrusted string can reach.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import base64
import hashlib
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

from ..errors import MailgateError
from .mailstate import canonical_json, sha256_hex
from .textsafe import sanitize_for_display

#: the agent's stated reason is an enum plus a short bounded note -- it is written
#: to the audit log, which must not become a second copy of the mailbox
REASON_CODES = (
    "p1_needs_action_today",
    "p2_this_week",
    "p3_fyi",
    "newsletter_or_bulk",
    "receipt_or_invoice",
    "waiting_on_reply",
    "duplicate_or_superseded",
    "other",
)


@dataclass
class ApprovalRequest:
    id: str
    mailbox: str
    account: str
    op: str
    message_key: str
    #: fixed-region facts, all server-resolved
    source_name: str
    target_name: str
    labels_added: tuple[str, ...]
    labels_removed: tuple[str, ...]
    thread_size: int
    #: untrusted, already sanitised for display
    subject: str
    sender: str
    suspected_injection: bool
    injection_signals: tuple[str, ...]
    reason_code: str
    reason_note: str
    prior_hash: str
    created: float = field(default_factory=time.monotonic)
    created_wall: float = field(default_factory=time.time)

    decided: bool = False
    accepted: bool = False
    outcome: dict | None = None
    _event: threading.Event = field(default_factory=threading.Event, repr=False)

    # ------------------------------------------------------------------ #
    def render(self) -> str:
        """The exact text Spencer sees.  Hashed into the commitment below."""
        lines = [
            f"account   : {self.account}   [{self.mailbox}]",
            f"operation : {self.op}",
        ]
        if self.op == "move_message":
            lines.append(f"move      : {self.source_name}  ->  {self.target_name}")
        if self.labels_added:
            lines.append(f"label +   : {', '.join(sorted(self.labels_added))}")
        if self.labels_removed:
            lines.append(f"label -   : {', '.join(sorted(self.labels_removed))}")
        if self.thread_size > 1:
            lines.append(
                f"thread    : {self.thread_size} messages -- the whole conversation is affected"
            )
        lines += [
            "-" * 64,
            f"subject   : {sanitize_for_display(self.subject, max_len=120)}",
            f"sender    : {sanitize_for_display(self.sender, max_len=120)}",
            f"agent says: [{self.reason_code}] {sanitize_for_display(self.reason_note, max_len=120)}",
        ]
        if self.suspected_injection:
            lines.append(
                "WARNING   : this message looks like a prompt-injection attempt "
                f"({', '.join(self.injection_signals)})"
            )
        return "\n".join(lines)

    def commitment(self) -> str:
        return sha256_hex(self.render().encode())

    def verification_code(self) -> str:
        """4 characters Spencer can compare against what the agent claims it asked for."""
        return base64.b32encode(bytes.fromhex(self.commitment()[:10]))[:4].decode()

    def audit_stub(self) -> dict:
        return {
            "approval_id": self.id,
            "rendered_commitment": self.commitment(),
            "verification_code": self.verification_code(),
        }


class ApprovalBroker:
    """Pending queue + executor.  One per server process."""

    def __init__(self, *, max_pending: int = 2, max_prompts_per_hour: int = 25):
        self._lock = threading.Lock()
        self._pending: dict[str, ApprovalRequest] = {}
        self._done: dict[str, ApprovalRequest] = {}
        self.max_pending = max_pending
        self.max_prompts_per_hour = max_prompts_per_hour
        self._prompt_times: list[float] = []
        self._executors: dict[str, Callable[[ApprovalRequest], dict]] = {}
        self.on_new: Callable[[ApprovalRequest], None] | None = None

    # ------------------------------------------------------------------ #
    def submit(
        self, req: ApprovalRequest, executor: Callable[[ApprovalRequest], dict]
    ) -> ApprovalRequest:
        """Queue a request.  Raises if the queue is being flooded.

        Capping the queue is a security control, not politeness: an agent that can
        queue dozens of near-identical prompts (subjects differing by a zero-width
        character) is farming a mis-tap.
        """
        now = time.monotonic()
        with self._lock:
            self._prompt_times = [t for t in self._prompt_times if now - t < 3600]
            if len(self._prompt_times) >= self.max_prompts_per_hour:
                raise MailgateError(
                    "approval-prompt budget exhausted for this hour", code="prompt_budget"
                )
            same_account = [r for r in self._pending.values() if r.mailbox == req.mailbox]
            if len(same_account) >= self.max_pending:
                raise MailgateError(
                    f"{len(same_account)} approvals already pending for this mailbox; "
                    "auto-denying to prevent attention exhaustion",
                    code="pending_queue_full",
                )
            self._pending[req.id] = req
            self._executors[req.id] = executor
            self._prompt_times.append(now)
        if self.on_new:
            self.on_new(req)
        return req

    def wait(self, req: ApprovalRequest, timeout: float) -> bool:
        """Block the caller for up to ``timeout`` seconds.  Returns True if decided."""
        return req._event.wait(timeout)

    def pending(self, mailbox: str | None = None) -> list[ApprovalRequest]:
        with self._lock:
            return [
                r for r in self._pending.values() if mailbox is None or r.mailbox == mailbox
            ]

    def get(self, request_id: str) -> ApprovalRequest | None:
        with self._lock:
            return self._pending.get(request_id) or self._done.get(request_id)

    # ------------------------------------------------------------------ #
    def decide(self, request_id: str, accept: bool, *, note: str = "") -> dict:
        """Called from the approval channel.  Executes immediately on accept."""
        with self._lock:
            req = self._pending.pop(request_id, None)
            executor = self._executors.pop(request_id, None)
            if req is None:
                return {"error": "no such pending approval"}
            self._done[request_id] = req
        req.accepted = accept
        if accept and executor is not None:
            try:
                req.outcome = executor(req)
            except MailgateError as exc:
                req.outcome = {"status": "denied", "error": exc.code, "detail": str(exc)}
            except Exception as exc:  # noqa: BLE001
                req.outcome = {"status": "unknown_outcome", "error": type(exc).__name__}
        else:
            req.outcome = {"status": "denied", "reason": note or "rejected by the mailbox owner"}
        req.decided = True
        req._event.set()
        return req.outcome

    def expire_stale(self, ttl_s: float = 3600.0) -> int:
        """Auto-deny anything nobody looked at.  Fail closed, loudly."""
        now = time.monotonic()
        n = 0
        for req in self.pending():
            if now - req.created > ttl_s:
                self.decide(req.id, False, note="expired without a decision")
                n += 1
        return n


def new_request_id() -> str:
    return "req_" + uuid.uuid4().hex[:10]
