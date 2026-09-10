"""On IMAP a naive read IS a mutation.  This is that trap, in miniature."""
# SPDX-License-Identifier: GPL-3.0-or-later
from conftest import first_handles, make


def test_no_read_path_changes_state(tmp_path):
    mg = make(tmp_path)
    fake = mg.accounts["demo"].backend
    mg.list_folders("demo")
    handles = first_handles(mg)
    for h in handles:
        mg.get_message("demo", h)
    assert fake.mutation_count == 0, "a read changed mailbox state"
    assert fake.read_count > 0


def test_reads_are_budgeted_separately_and_logged(tmp_path):
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    mg.get_message("demo", h)
    recs = [r for r in _records(mg) if r.get("op") == "get_message"]
    assert recs and recs[-1]["type"] == "read"
    # body disclosure is recorded by message key so exfiltration is reconstructable
    assert recs[-1]["message_key"]
    assert "body" not in recs[-1] and "subject" not in recs[-1]


def _records(mg):
    import json

    out = []
    for p in sorted(mg.audit.dir.glob("*.jsonl")):
        for line in p.read_text().splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out
