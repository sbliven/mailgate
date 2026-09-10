"""Source-level regression lint.

This is a LINT, not a boundary -- it is defeated by string construction and by
dependencies that issue requests for you.  The actual controls are the request
allowlist in httpgate.py and the command allowlist in imap.py, which are tested
separately below.  The lint still earns its place: it catches an accidental
reintroduction during a refactor.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
import pathlib

import pytest

from mailgate.backends import httpgate
from mailgate.backends.gmail import build_modify_body
from mailgate.backends.imap import check_command
from mailgate.errors import BackendError

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "mailgate"


def _code_lines(path: pathlib.Path) -> list[str]:
    """Strip docstrings and comments so prose about the forbidden verbs is allowed."""
    import ast

    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body[0].value.value = ""
    return ast.unparse(tree).splitlines()


FORBIDDEN_SUBSTRINGS = [
    "smtplib", "sendMail", "messages.trash", "messages/trash", "batchDelete",
]


def _executable_lines(path: pathlib.Path) -> str:
    """Docstrings stripped, and the deny-list declarations excluded -- a module is
    allowed to *name* a verb in order to forbid it."""
    keep = []
    for line in _code_lines(path):
        if line.lstrip().startswith(("FORBIDDEN_", "ALLOWED_")):
            continue
        keep.append(line)
    return "\n".join(keep)


@pytest.mark.parametrize("mod", ["gmail.py", "graph.py", "imap.py", "fake.py", "base.py"])
def test_adapters_contain_no_destructive_call(mod):
    code = _executable_lines(SRC / "backends" / mod)
    for bad in FORBIDDEN_SUBSTRINGS:
        assert bad not in code, f"{mod} mentions {bad} in executable code"
    assert "EXPUNGE" not in code
    assert "\\Deleted" not in code


def test_no_module_imports_smtplib():
    for path in SRC.rglob("*.py"):
        assert "import smtplib" not in path.read_text()


@pytest.mark.parametrize("method,host,path", [
    ("DELETE", "gmail.googleapis.com", "/gmail/v1/users/me/messages/abc"),
    ("POST", "gmail.googleapis.com", "/gmail/v1/users/me/messages/abc/trash"),
    ("POST", "gmail.googleapis.com", "/gmail/v1/users/me/messages/send"),
    ("DELETE", "graph.microsoft.com", "/v1.0/me/messages/abc"),
    ("POST", "graph.microsoft.com", "/v1.0/me/sendMail"),
    ("POST", "graph.microsoft.com", "/v1.0/me/messages/abc/createReply"),
    ("GET", "exfil.test", "/collect"),
    ("POST", "gmail.googleapis.com", "/gmail/v1/users/me/settings/autoForwarding"),
])
def test_request_chokepoint_blocks_everything_dangerous(method, host, path):
    with pytest.raises(BackendError) as e:
        httpgate.check_request(method, host, path)
    assert e.value.code == "request_not_allowlisted"


def test_request_chokepoint_allows_exactly_what_is_needed():
    httpgate.check_request("POST", "gmail.googleapis.com",
                           "/gmail/v1/users/me/messages/abc/modify")
    httpgate.check_request("POST", "graph.microsoft.com", "/v1.0/me/messages/abc/move")
    httpgate.check_request("PATCH", "graph.microsoft.com", "/v1.0/me/messages/abc")


@pytest.mark.parametrize("cmd,code", [
    ("EXPUNGE", "imap_command_blocked"),
    ("CLOSE", "imap_command_blocked"),
    ("SELECT INBOX", "imap_command_blocked"),          # SELECT clears \Recent
    ("DELETE INBOX.Old", "imap_command_blocked"),
    ("APPEND INBOX {10}", "imap_command_blocked"),
    ("UID FETCH 1 BODY[]", "mutating_read_blocked"),   # sets \Seen
    ("UID EXPUNGE 1", "imap_command_blocked"),
])
def test_imap_command_allowlist(cmd, code):
    with pytest.raises(BackendError) as e:
        check_command(cmd)
    assert e.value.code == code


def test_imap_reads_use_peek_and_examine():
    check_command("EXAMINE INBOX")
    check_command("UID FETCH 1 BODY.PEEK[]")
    check_command("UID MOVE 1 INBOX.Archive")


def test_imap_deleted_flag_cannot_be_set():
    with pytest.raises(BackendError) as e:
        check_command("UID STORE 1 +FLAGS (x)", flags=("\\Deleted",))
    assert e.value.code == "imap_flag_blocked"


def test_gmail_modify_body_is_the_only_construction_path():
    with pytest.raises(BackendError):
        build_modify_body(add_ids=("TRASH",), remove_ids=(), allow_inbox_removal=False)
    with pytest.raises(BackendError):
        build_modify_body(add_ids=(), remove_ids=("INBOX",), allow_inbox_removal=False)
    # the single permitted INBOX removal: move_message
    assert build_modify_body(add_ids=("L1",), remove_ids=("INBOX",),
                             allow_inbox_removal=True)["removeLabelIds"] == ["INBOX"]


def test_live_adapters_refuse_to_construct():
    from mailgate.backends import gmail, graph, imap

    for cls in (gmail.GmailBackend, graph.GraphBackend, imap.ImapBackend):
        with pytest.raises(BackendError) as e:
            cls(None)
        assert e.value.code == "adapter_not_approved"
