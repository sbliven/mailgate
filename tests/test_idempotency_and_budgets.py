# SPDX-License-Identifier: GPL-3.0-or-later
import time

import pytest

from conftest import first_handles, make, write_policy


def test_same_key_same_intent_is_a_duplicate(tmp_path):
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    r1 = mg.move_message("demo", h, "Archive", "p3_fyi", "x", "k1")
    r2 = mg.move_message("demo", h, "Archive", "p3_fyi", "x", "k1")
    assert r1["status"] == "applied"
    assert r2["status"] == "duplicate_ignored"
    assert r2["original_status"] == "applied"      # not merely "already done"
    assert r2["audit_id"] == r1["audit_id"]
    assert mg.accounts["demo"].backend.mutation_count == 1


def test_same_key_different_intent_is_an_error_not_a_duplicate(tmp_path):
    """Returning duplicate_ignored for a DIFFERENT action is the worst possible
    answer: it tells the agent something happened that did not."""
    mg = make(tmp_path)
    handles = first_handles(mg)
    mg.move_message("demo", handles[0], "Archive", "p3_fyi", "x", "k1")
    r = mg.move_message("demo", handles[1], "Receipts", "p3_fyi", "x", "k1")
    assert r["status"] == "idempotency_key_reuse"


def test_server_side_fingerprint_catches_a_regenerated_key(tmp_path):
    """An LLM that invents a fresh UUID on retry must not defeat idempotency."""
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    mg.move_message("demo", h, "Archive", "p3_fyi", "x", "key-one")
    r = mg.move_message("demo", h, "Archive", "p3_fyi", "x", "key-two")
    assert r["status"] == "duplicate_ignored"
    assert "fingerprint" in r["note"]


def test_missing_idempotency_key_is_refused(tmp_path):
    from mailgate.errors import MailgateError

    mg = make(tmp_path)
    h = first_handles(mg)[0]
    with pytest.raises(MailgateError) as e:
        mg.move_message("demo", h, "Archive", "p3_fyi", "x", "")
    assert e.value.code == "missing_idempotency_key"


def test_in_flight_rows_are_reported_never_retried(tmp_path):
    """Provider applied it, response lost, server died: the row that survives must
    demand a human, not a retry."""
    from mailgate.core.store import Store

    state = tmp_path / "st"
    mg = make(tmp_path, state=state)
    s = mg.store
    s.begin_mutation("fake:fixture-mailbox-0001", "orphan", "move_message", "fp-x")
    mg2 = make(tmp_path, state=state)
    assert mg2.reconciliation
    assert mg2.reconciliation[0]["status"] == "unknown_outcome"
    assert "reconcile" in mg2.reconciliation[0]["action"]


def test_budgets_survive_a_restart(tmp_path):
    """A per-session counter is useless against an agent that can respawn the
    server, which under stdio it can."""
    state = tmp_path / "st"
    mg = make(tmp_path, mph=2, state=state)
    handles = first_handles(mg)
    assert mg.move_message("demo", handles[0], "Archive", "p3_fyi", "x", "a")["status"] == "applied"
    assert mg.move_message("demo", handles[1], "Archive", "p3_fyi", "x", "b")["status"] == "applied"
    mg2 = make(tmp_path, mph=2, state=state)
    r = mg2.move_message("demo", handles[2], "Archive", "p3_fyi", "x", "c")
    assert r["status"] == "rate_limited"


def test_per_message_brake(tmp_path):
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    assert mg.move_message("demo", h, "Archive", "p3_fyi", "x", "a")["status"] == "applied"
    # a genuinely different action on the same message within the hour
    r = mg.apply_labels("demo", h, add=["p1"], reason_code="p1_needs_action_today",
                        reason_note="x", idempotency_key="b")
    assert r["status"] in ("rate_limited", "stale_handle")


def test_denials_charge_their_own_budget(tmp_path):
    """If the limiter runs after validation, denied calls are free and unlimited."""
    mg = make(tmp_path)
    handles = first_handles(mg)
    for i, h in enumerate(handles):
        mg.move_message("demo", h, "Archive-2024", "other", "x", f"d{i}")
    used = mg.store.cx.execute(
        "SELECT count FROM counters WHERE bucket='denials'"
    ).fetchone()
    assert used and used["count"] >= len(handles)


def test_backwards_clock_refuses_mutations(tmp_path):
    from mailgate.core.store import ClockWentBackwards, Store

    s = Store(tmp_path / "st")
    s.cx.execute(
        "INSERT INTO meta(k,v) VALUES('last_wall',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
        (str(time.time() + 7200),),
    )
    s2 = Store(tmp_path / "st")
    with pytest.raises(ClockWentBackwards):
        s2.charge("fake:mb", "mutations", 10)
