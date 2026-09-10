"""The canonical serializer -- the primitive every other safety check rests on."""
# SPDX-License-Identifier: GPL-3.0-or-later
import json

from mailgate.core.mailstate import (
    MessageState,
    StateDelta,
    apply_delta_to_state,
    canonical_json,
    message_key,
)


def test_label_order_does_not_change_the_hash():
    a = MessageState(backend="gmail", label_ids=("INBOX", "UNREAD", "Label_9"))
    b = MessageState(backend="gmail", label_ids=("Label_9", "INBOX", "UNREAD"))
    assert a.state_hash() == b.state_hash()


def test_volatile_tokens_are_excluded_from_the_precondition_hash():
    """etag/modseq change on every unrelated write; including them would make every
    mutation permanently stale -- a liveness bug that looks like a safety feature."""
    a = MessageState(backend="graph", parent_folder_id="F1", categories=("p1",), etag="W/1")
    b = MessageState(backend="graph", parent_folder_id="F1", categories=("p1",), etag="W/2")
    assert a.state_hash() == b.state_hash()
    assert a.record()["etag"] != b.record()["etag"]


def test_delta_inverse_round_trips_on_all_three_shapes():
    cases = [
        (MessageState(backend="gmail", label_ids=("INBOX", "UNREAD")),
         StateDelta(add_labels=("L1",), remove_labels=("INBOX",))),
        (MessageState(backend="graph", parent_folder_id="F1", categories=("a",)),
         StateDelta(to_folder="F2", from_folder="F1", add_categories=("b",))),
        (MessageState(backend="imap", mailbox="INBOX", uidvalidity=1, uid=5, flags=("p1",)),
         StateDelta(to_folder="Arch", from_folder="INBOX", add_flags=("p2",))),
    ]
    for state, delta in cases:
        moved = apply_delta_to_state(state, delta)
        back = apply_delta_to_state(moved, delta.inverse())
        assert back.state_hash() == state.state_hash()


def test_canonical_json_is_frozen():
    """A golden value.  If this changes, every historical audit record stops
    verifying and the operator learns to ignore `mailgate verify`."""
    assert canonical_json({"b": 1, "a": [3, 2]}) == b'{"a":[3,2],"b":1}'
    assert canonical_json({"k": "é"}) == b'{"k":"\\u00e9"}'


def test_message_key_ignores_rfc822_message_id():
    """Message-ID is optional, duplicated and sender-controlled, so identity must
    not depend on it."""
    k1 = message_key("fake:mb", "fake", "id-1")
    k2 = message_key("fake:mb", "fake", "id-2")
    assert k1 != k2
    assert message_key("fake:other", "fake", "id-1") != k1
