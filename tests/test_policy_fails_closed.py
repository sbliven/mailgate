# SPDX-License-Identifier: GPL-3.0-or-later
import os

import pytest

from conftest import FIXTURES, make, write_policy
from mailgate.errors import ConfigError


def _policy(tmp_path, body: str):
    p = tmp_path / "p.toml"
    p.write_text(body)
    os.chmod(p, 0o600)
    return p


BASE = """
policy_version = 1
mode = "training"
[accounts.demo]
backend = "fake"
fixture = "{fx}"
"""


def load(tmp_path, extra: str):
    from mailgate.core.policy import load_policy

    return load_policy(_policy(tmp_path, BASE.format(fx=FIXTURES / "mailbox_folders.json") + extra))


def test_unknown_key_is_a_startup_error(tmp_path):
    with pytest.raises(ConfigError) as e:
        load(tmp_path, 'move_allowlist_typo = ["Archive"]\n')
    assert e.value.code == "unknown_config_key"


def test_destination_must_be_attested(tmp_path):
    with pytest.raises(ConfigError) as e:
        load(tmp_path, 'move_allowlist = ["Archive"]\n')
    assert e.value.code == "unattested_destination"


def test_confusable_destinations_refuse_to_start(tmp_path):
    """Cyrillic A vs Latin A.  Folding to ACCEPT a match would move mail into the
    wrong folder; folding to REFUSE is the only safe direction."""
    with pytest.raises(ConfigError) as e:
        load(
            tmp_path,
            'move_allowlist = ["Archive", "Аrchive"]\n'
            'attest_no_retention = ["Archive", "Аrchive"]\n',
        )
    assert e.value.code == "confusable_config"


def test_reserved_label_cannot_be_allowlisted(tmp_path):
    with pytest.raises(ConfigError) as e:
        load(tmp_path, 'label_allowlist = ["INBOX"]\n')
    assert e.value.code == "reserved_label_in_allowlist"


def test_cmd_secret_ref_is_rejected(tmp_path):
    with pytest.raises(ConfigError) as e:
        load(tmp_path, 'secret_ref = "cmd:cat /tmp/tok"\n')
    assert e.value.code == "forbidden_secret_ref"


def test_world_writable_policy_is_refused(tmp_path):
    from mailgate.core.policy import load_policy

    p = _policy(tmp_path, BASE.format(fx=FIXTURES / "mailbox_folders.json"))
    os.chmod(p, 0o666)
    with pytest.raises(ConfigError) as e:
        load_policy(p)
    assert e.value.code == "insecure_path"


def test_destructive_and_shared_destinations_refuse_at_bind(tmp_path):
    from mailgate.engine import open_mailgate

    for dest, code in [
        ("Archive-2024", "destructive_destination"),   # benign name, \Trash attribute
        ("Team-Shared", "shared_destination"),
        ("Cleanup", "destination_automation"),
        ("Nonexistent", "unresolved_config_value"),
    ]:
        p = _policy(
            tmp_path,
            BASE.format(fx=FIXTURES / "mailbox_folders.json")
            + f'move_allowlist = ["{dest}"]\nattest_no_retention = ["{dest}"]\n',
        )
        with pytest.raises(ConfigError) as e:
            open_mailgate(p, tmp_path / ("st-" + dest))
        assert e.value.code == code, (dest, e.value.code)


def test_protect_folders_denies_reads_too(tmp_path):
    """"read-only, never a source or destination" still let the agent read every
    legal message; read-then-exfiltrate is the dominant loss."""
    from mailgate.errors import PolicyDenied

    mg = make(tmp_path)
    with pytest.raises(PolicyDenied) as e:
        mg.list_messages("demo", "Legal")
    assert e.value.code == "read_denied"
