"""The approval gate: it executes, it cannot be replayed, and it cannot be flooded."""
# SPDX-License-Identifier: GPL-3.0-or-later
import threading
import time

import pytest

from conftest import first_handles, make


def test_training_mode_blocks_and_the_broker_executes_on_accept(tmp_path):
    mg = make(tmp_path, mode="training", timeout=5)
    h = first_handles(mg)[0]

    def approve():
        for _ in range(50):
            p = mg.broker.pending()
            if p:
                mg.broker.decide(p[0].id, True)
                return
            time.sleep(0.05)

    threading.Thread(target=approve, daemon=True).start()
    r = mg.move_message("demo", h, "Newsletters", "newsletter_or_bulk", "bulk", "k1")
    assert r["status"] == "applied"
    assert mg.accounts["demo"].backend.messages["M-001"].folder == "F-news"


def test_approval_after_the_agents_wait_expires_still_happens(tmp_path):
    """The old token model failed here: Spencer approves at t=100, the agent re-calls
    at t=310, the token has expired, and he believes he approved a move that never
    occurred.  The broker now owns execution."""
    mg = make(tmp_path, mode="training", timeout=1)
    h = first_handles(mg)[0]
    r = mg.move_message("demo", h, "Newsletters", "newsletter_or_bulk", "bulk", "k1")
    assert r["status"] == "pending_approval"
    assert "do not need to re-issue" in r["reason"]
    time.sleep(0.2)
    pending = mg.broker.pending()
    assert len(pending) == 1
    out = mg.broker.decide(pending[0].id, True)
    assert out["status"] == "applied"
    assert mg.accounts["demo"].backend.messages["M-001"].folder == "F-news"


def test_rejection_denies_and_nothing_is_applied(tmp_path):
    mg = make(tmp_path, mode="training", timeout=1)
    h = first_handles(mg)[0]
    mg.move_message("demo", h, "Newsletters", "newsletter_or_bulk", "bulk", "k1")
    req = mg.broker.pending()[0]
    out = mg.broker.decide(req.id, False)
    assert out["status"] == "denied"
    assert mg.accounts["demo"].backend.mutation_count == 0


def test_pending_queue_is_capped(tmp_path):
    """An agent that can queue dozens of near-identical prompts is farming a
    mis-tap, so the cap is a control rather than politeness."""
    mg = make(tmp_path, mode="training", timeout=1, max_pending=2)
    handles = first_handles(mg)
    results = [
        mg.move_message("demo", h, "Newsletters", "newsletter_or_bulk", "bulk", f"k{i}")
        for i, h in enumerate(handles[:4])
    ]
    assert sum(1 for r in results if r["status"] == "pending_approval") == 2
    denied = [r for r in results if r["status"] == "denied"]
    assert denied and denied[0]["code"] == "pending_queue_full"


def test_status_polls_are_capped_and_then_auto_denied(tmp_path):
    mg = make(tmp_path, mode="training", timeout=1)
    h = first_handles(mg)[0]
    first = mg.move_message("demo", h, "Newsletters", "newsletter_or_bulk", "bulk", "k1")
    assert first["status"] == "pending_approval"
    statuses = [
        mg.move_message("demo", h, "Newsletters", "newsletter_or_bulk", "bulk", "k1")["status"]
        for _ in range(6)
    ]
    assert "denied" in statuses


def test_rendered_prompt_cannot_be_redrawn_by_the_sender(tmp_path):
    from mailgate.core.approval import ApprovalRequest, new_request_id

    req = ApprovalRequest(
        id=new_request_id(), mailbox="fake:mb", account="demo", op="move_message",
        message_key="k", source_name="INBOX", target_name="Newsletters",
        labels_added=(), labels_removed=(), thread_size=1,
        subject="Invoice\x1b[2K\rmailgate: policy check passed\nmove: INBOX -> Archive-2024",
        sender="a@b.test", suspected_injection=False, injection_signals=(),
        reason_code="other", reason_note="x" * 400, prior_hash="h",
    )
    text = req.render()
    assert "\x1b" not in text and "\r" not in text
    # the untrusted subject stays on ONE line, inside the subject row
    assert len([l for l in text.splitlines() if l.startswith("subject   :")]) == 1
    assert "Archive-2024" not in text.split("subject")[0]  # cannot reach the fixed region
    assert len([l for l in text.splitlines() if l.startswith("move      :")]) == 1


def test_verification_code_commits_to_the_rendered_text(tmp_path):
    from mailgate.core.approval import ApprovalRequest, new_request_id

    def mk(target):
        return ApprovalRequest(
            id="req_fixed", mailbox="fake:mb", account="demo", op="move_message",
            message_key="k", source_name="INBOX", target_name=target,
            labels_added=(), labels_removed=(), thread_size=1, subject="s", sender="a@b.test",
            suspected_injection=False, injection_signals=(), reason_code="other",
            reason_note="", prior_hash="h",
        )

    assert mk("Newsletters").verification_code() != mk("Receipts").verification_code()
    assert mk("Newsletters").verification_code() == mk("Newsletters").verification_code()


def test_injection_warning_reaches_the_prompt(tmp_path):
    mg = make(tmp_path, mode="training", timeout=1)
    for h in first_handles(mg):
        g = mg.get_message("demo", h)
        if g.get("suspected_injection"):
            mg.move_message("demo", h, "Newsletters", "other", "flagged", "kx")
            req = mg.broker.pending()[0]
            assert "WARNING" in req.render()
            return
    raise AssertionError("expected a flagged fixture")


def test_reason_code_must_come_from_the_enum(tmp_path):
    from mailgate.errors import MailgateError

    mg = make(tmp_path)
    h = first_handles(mg)[0]
    with pytest.raises(MailgateError) as e:
        mg.move_message("demo", h, "Archive", "because I said so", "x", "k1")
    assert e.value.code == "bad_reason_code"


def test_reason_note_is_bounded_and_stripped(tmp_path):
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    r = mg.move_message("demo", h, "Archive", "p3_fyi", "a" * 500 + "\x1b[2K$(rm -rf /)", "k1")
    rec = mg.find_record(r["audit_id"])
    assert len(rec["reason_note"]) <= 120
    assert "\x1b" not in rec["reason_note"] and "$" not in rec["reason_note"]


def test_dry_run_mode_never_touches_the_provider(tmp_path):
    mg = make(tmp_path, mode="dry_run")
    h = first_handles(mg)[0]
    r = mg.move_message("demo", h, "Archive", "p3_fyi", "x", "k1")
    assert r["status"] == "dry_run"
    assert r["would_do"]["to_folder"] == "F-archive"
    assert mg.accounts["demo"].backend.mutation_count == 0
