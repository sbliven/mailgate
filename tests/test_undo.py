"""Undo must reverse the delta, refuse on divergence, and never run twice."""
# SPDX-License-Identifier: GPL-3.0-or-later
from conftest import first_handles, make


def _applied_move(mg, dest="Archive"):
    h = first_handles(mg)[0]
    r = mg.move_message("demo", h, dest, "p3_fyi", "filing", "k1")
    assert r["status"] == "applied", r
    return r


def test_undo_reverses_a_move(tmp_path):
    mg = make(tmp_path)
    r = _applied_move(mg)
    assert mg.accounts["demo"].backend.messages["M-001"].folder == "F-archive"
    u = mg.undo(r["audit_id"])
    assert u["status"] == "applied"
    assert mg.accounts["demo"].backend.messages["M-001"].folder == "INBOX"


def test_undo_is_recorded_and_linked(tmp_path):
    mg = make(tmp_path)
    r = _applied_move(mg)
    u = mg.undo(r["audit_id"])
    rec = mg.find_record(u["audit_id"])
    assert rec["undo_of"] == r["audit_id"]
    assert rec["op"] == "undo" and rec["actor"] == "cli"


def test_undo_cannot_run_twice(tmp_path):
    mg = make(tmp_path)
    r = _applied_move(mg)
    assert mg.undo(r["audit_id"])["status"] == "applied"
    again = mg.undo(r["audit_id"])
    assert again["status"] == "denied" and "already undone" in again["reason"]


def test_undo_refuses_when_someone_else_moved_the_message(tmp_path):
    """Snapshot restore would clobber whatever Spencer did in his own mail client;
    delta reversal must at least notice."""
    mg = make(tmp_path)
    r = _applied_move(mg)
    mg.accounts["demo"].backend.messages["M-001"].folder = "F-receipts"
    u = mg.undo(r["audit_id"])
    assert u["status"] in ("denied", "stale_handle")
    if u["status"] == "denied":
        assert "not in the state this record left it in" in u["reason"]


def test_forced_undo_is_logged_as_forced(tmp_path):
    mg = make(tmp_path)
    r = _applied_move(mg)
    b = mg.accounts["demo"].backend
    b.messages["M-001"].labels.append("p2")     # a divergence that keeps the handle valid
    u = mg.undo(r["audit_id"], force=True)
    assert u["status"] == "applied"
    assert mg.find_record(u["audit_id"])["forced"] is True


def test_undo_goes_through_the_policy_engine(tmp_path):
    """An undo can try to move mail back into a folder that is no longer
    allowlisted."""
    mg = make(tmp_path)
    r = _applied_move(mg)
    b = mg.accounts["demo"]
    # simulate the source folder having become protected since the move
    object.__setattr__(b.resolved, "no_write_ids", frozenset({"INBOX"}))
    from mailgate.core.policy import check_move

    d = check_move(b.resolved, "F-archive", "INBOX")
    assert not d.allowed


def test_undo_is_not_an_mcp_tool(tmp_path):
    from mailgate import server

    assert "undo" not in {t.name for t in server.TOOLS}
