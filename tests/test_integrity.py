"""Data integrity: identity, concurrency, cursors, the audit chain, undo."""
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import os
import time

import pytest

from conftest import FIXTURES, first_handles, make


def test_uidvalidity_bump_makes_the_handle_stale(tmp_path):
    """The likeliest cause of mangling the wrong message: a UID means nothing once
    UIDVALIDITY changes."""
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    mg.accounts["demo"].backend.bump_uidvalidity()
    r = mg.move_message("demo", h, "Archive", "p3_fyi", "x", "k1")
    assert r["status"] == "stale_handle"
    assert mg.accounts["demo"].backend.mutation_count == 0


def test_cursor_is_invalidated_rather_than_silently_resumed(tmp_path):
    mg = make(tmp_path)
    page = mg.list_messages("demo", "INBOX", limit=2)
    assert page["next_cursor"]
    mg.accounts["demo"].backend.bump_uidvalidity()
    nxt = mg.list_messages("demo", "INBOX", cursor=page["next_cursor"], limit=2)
    assert nxt["status"] == "cursor_invalidated"
    assert "do NOT report it as fully triaged" in nxt["retry"]


def test_state_change_between_read_and_apply_is_refused(tmp_path):
    """TOCTOU: the compare-and-set must see the same state the decision was made on."""
    mg = make(tmp_path)
    b = mg.accounts["demo"].backend
    from mailgate.backends.base import MessageRef
    from mailgate.core.mailstate import StateDelta

    h = first_handles(mg)[0]
    ref = MessageRef.parse(h)
    prior = b.read_state(ref)
    b.messages[ref.message_id].labels.append("p2")     # someone else's edit
    res = b.apply(ref, StateDelta(to_folder="F-archive", from_folder="INBOX"), prior)
    assert res.status == "stale_handle"


def test_move_is_refused_when_the_server_cannot_do_it_atomically(tmp_path):
    mg = make(tmp_path, fixture="mailbox_no_move.json")
    h = first_handles(mg)[0]
    r = mg.move_message("demo", h, "Archive", "p3_fyi", "x", "k1")
    assert r["status"] == "denied"
    assert "refusing a non-atomic move" in r.get("note", "") or "refusing" in str(r)


def test_copy_only_server_reports_copied_not_removed_and_tracks_the_duplicate(tmp_path):
    """Refusing to finish a COPY with \\Deleted is right, but the duplicate must be
    accounted for or repeated moves fill the quota."""
    mg = make(tmp_path, fixture="mailbox_copy_only.json")
    h = first_handles(mg)[0]
    r = mg.move_message("demo", h, "Archive", "p3_fyi", "x", "k1")
    assert r["status"] == "copied_not_removed"
    assert r["outstanding_copy_pending"] == 1
    assert "reconcil" in json.dumps(r) or r["note"]


def test_second_move_of_the_same_message_into_the_same_place_is_refused(tmp_path):
    mg = make(tmp_path, fixture="mailbox_copy_only.json")
    handles = first_handles(mg)
    r1 = mg.move_message("demo", handles[0], "Archive", "p3_fyi", "x", "k1")
    assert r1["status"] == "copied_not_removed"
    r2 = mg.move_message("demo", handles[0], "Archive", "p3_fyi", "x", "k2")
    # the per-message hourly brake catches it first; either refusal is acceptable
    assert r2["status"] in ("rate_limited", "duplicate_ignored", "denied")


def test_audit_records_prior_and_observed_post(tmp_path):
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    r = mg.move_message("demo", h, "Archive", "p3_fyi", "filing", "k1")
    assert r["status"] == "applied"
    rec = mg.find_record(r["audit_id"])
    assert rec["prior"]["mailbox"] == "INBOX"
    assert rec["post"]["mailbox"] == "F-archive"      # observed, not merely intended
    assert rec["delta"]["from_folder"] == "INBOX"


def test_audit_chain_detects_tampering(tmp_path):
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    mg.move_message("demo", h, "Archive", "p3_fyi", "x", "k1")
    assert mg.audit.verify().ok
    path = sorted(mg.audit.dir.glob("*.jsonl"))[0]
    os.chmod(path, 0o600)
    path.write_text(path.read_text().replace("F-archive", "F-trap-trash"))
    v = mg.audit.verify()
    assert not v.ok and v.problems


def test_audit_chain_detects_a_removed_record(tmp_path):
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    mg.move_message("demo", h, "Archive", "p3_fyi", "x", "k1")
    path = sorted(mg.audit.dir.glob("*.jsonl"))[0]
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n")
    v = mg.audit.verify()
    assert not v.ok


def test_torn_final_line_is_distinguished_from_tampering(tmp_path):
    mg = make(tmp_path)
    path = sorted(mg.audit.dir.glob("*.jsonl"))[0]
    with open(path, "a") as fh:
        fh.write('{"partial": tr')
    v = mg.audit.verify()
    assert v.incomplete_tail
    assert any("torn final line" in p for p in v.problems)


def test_denials_are_logged_too(tmp_path):
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    mg.move_message("demo", h, "Archive-2024", "other", "x", "k1")
    recs = [
        json.loads(l)
        for p in sorted(mg.audit.dir.glob("*.jsonl"))
        for l in p.read_text().splitlines()
        if l.strip()
    ]
    assert any(r.get("decision") == "denied" and r.get("code") == "destructive_destination"
               for r in recs)


def test_two_aliases_for_one_mailbox_refuse_to_start(tmp_path):
    """Both budgets and the writer lock key on the mailbox, so two aliases would
    double every budget and let two adapters race."""
    from mailgate.engine import open_mailgate
    from mailgate.errors import ConfigError

    p = tmp_path / "dup.toml"
    fx = FIXTURES / "mailbox_folders.json"
    p.write_text(
        f"""policy_version = 1
mode = "training"
[accounts.a]
backend = "fake"
fixture = "{fx}"
[accounts.b]
backend = "fake"
fixture = "{fx}"
"""
    )
    os.chmod(p, 0o600)
    with pytest.raises(ConfigError) as e:
        open_mailgate(p, tmp_path / "st")
    assert e.value.code == "duplicate_mailbox"


def test_account_lock_is_a_file_lock_so_the_cli_contends_too(tmp_path):
    from mailgate.core.store import Store
    from mailgate.errors import MailgateError

    s1 = Store(tmp_path / "st")
    s2 = Store(tmp_path / "st")
    with s1.account_lock("fake:mb"):
        with pytest.raises(MailgateError) as e:
            with s2.account_lock("fake:mb"):
                pass
    assert e.value.code == "account_busy"
