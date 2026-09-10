"""The central threat: destroying or hiding mail without a delete verb."""
# SPDX-License-Identifier: GPL-3.0-or-later
import pytest

from conftest import first_handles, make


def test_move_into_a_trash_attributed_folder_is_refused(tmp_path):
    """The folder is called "Archive-2024".  Its attribute is \\Trash.  Name-based
    checks pass it; attribute-based checks catch it."""
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    r = mg.move_message("demo", h, "Archive-2024", "other", "looks fine", "k1")
    assert r["status"] == "denied"
    assert r["code"] == "destructive_destination"


def test_a_folder_merely_named_trash_is_not_treated_as_destructive(tmp_path):
    """The converse case.  It is refused for not being allowlisted, NOT for its
    name -- which is the correct reason and keeps the model honest."""
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    r = mg.move_message("demo", h, "Trash", "other", "x", "k2")
    assert r["status"] == "denied"
    assert r["code"] == "destination_not_allowlisted"


@pytest.mark.parametrize("dest,code", [
    ("Quarantine", "destructive_destination"),   # \Junk
    ("Sent", "destructive_destination"),         # \Sent
    ("Team-Shared", "shared_destination"),
    ("Cleanup", "destination_automation"),
])
def test_every_destructive_or_leaky_destination_is_refused(tmp_path, dest, code):
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    r = mg.move_message("demo", h, dest, "other", "x", f"k-{dest}")
    assert (r["status"], r["code"]) == ("denied", code)


def _refused(mg, handle, **labels):
    """Either a denied result or a refusal exception counts -- both mean the
    mutation did not happen.  Returns the refusal code."""
    from mailgate.errors import MailgateError

    try:
        r = mg.apply_labels("demo", handle, reason_code="other", idempotency_key="k", **labels)
    except MailgateError as exc:
        return exc.code
    assert r["status"] == "denied", r
    return r["code"]


@pytest.mark.parametrize("labels", [
    {"remove": ["INBOX"]},        # archive-and-hide
    {"remove": ["UNREAD"]},       # mark read: hides it from the human's own triage
    {"add": ["TRASH"]},           # deletion, on Gmail
    {"add": ["SPAM"]},
    {"remove": ["STARRED"]},      # destroys the human's triage state
    {"add": ["\\Seen"]},
    {"add": ["CATEGORY_PROMOTIONS"]},
])
def test_reserved_labels_can_be_neither_added_nor_removed(tmp_path, labels):
    mg = make(tmp_path)
    h = first_handles(mg)[0]
    assert _refused(mg, h, **labels) in ("reserved_label", "unknown_label")


def test_unknown_label_is_refused_not_passed_through(tmp_path):
    """Graph accepts arbitrary category strings and never validates them, so a gap
    here writes attacker-chosen text into the mailbox: a covert channel."""
    from mailgate.errors import MailgateError

    mg = make(tmp_path)
    h = first_handles(mg)[0]
    with pytest.raises(MailgateError) as e:
        mg.apply_labels("demo", h, add=["exfil-AAAA"], reason_code="other",
                        idempotency_key="k")
    assert e.value.code == "unknown_label"


def test_source_protected_folder_cannot_be_emptied(tmp_path):
    mg = make(tmp_path)
    # Legal is unreadable, so there is no handle for it through the tool surface at
    # all -- but assert the source check independently.
    b = mg.accounts["demo"]
    from mailgate.core.policy import check_move

    d = check_move(b.resolved, "F-legal", "F-archive")
    assert not d.allowed and d.code == "source_protected"


def test_no_tool_can_change_mode_or_policy(tmp_path):
    mg = make(tmp_path)
    from mailgate import server

    names = {t.name for t in server.TOOLS}
    assert names == {
        "list_accounts", "list_folders", "list_messages", "get_message",
        "apply_labels", "move_message",
    }
    for forbidden in ("set_mode", "reload_config", "undo", "delete_message", "send",
                      "create_label", "raw_request", "execute"):
        assert forbidden not in names
