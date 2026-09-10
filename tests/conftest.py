# SPDX-License-Identifier: GPL-3.0-or-later
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

FIXTURES = ROOT / "tests" / "fixtures"

POLICY_TEMPLATE = """
policy_version = 1
mode = "{mode}"

[limits]
mutations_per_hour = {mph}
mutations_per_day = 200
approval_timeout_s = {timeout}
max_pending_approvals = {max_pending}
max_status_polls = 3

[accounts.demo]
backend = "fake"
fixture = "{fixture}"
move_allowlist = ["Archive", "Newsletters", "Receipts", "ToRead"]
label_allowlist = ["p1", "p2", "p3", "waiting", "fyi"]
protect_folders = ["Legal"]
attest_no_retention = ["Archive", "Newsletters", "Receipts", "ToRead"]
"""


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    return tmp_path


def write_policy(tmp_path: Path, *, mode="auto", fixture="mailbox_folders.json",
                 mph=40, timeout=2, max_pending=2, extra="") -> Path:
    p = tmp_path / "policy.toml"
    p.write_text(
        POLICY_TEMPLATE.format(
            mode=mode, fixture=str(FIXTURES / fixture), mph=mph, timeout=timeout,
            max_pending=max_pending,
        )
        + extra
    )
    os.chmod(p, 0o600)
    return p


@pytest.fixture
def mg(tmp_path):
    from mailgate.engine import open_mailgate

    return open_mailgate(write_policy(tmp_path), tmp_path / "state")


def make(tmp_path, **kw):
    from mailgate.engine import open_mailgate

    state = kw.pop("state", None) or (tmp_path / ("state" + str(len(list(tmp_path.iterdir())))))
    return open_mailgate(write_policy(tmp_path, **kw), state)


def first_handles(mg, folder="INBOX", n=8):
    return [m["handle"] for m in mg.list_messages("demo", folder, limit=n)["messages"]]
