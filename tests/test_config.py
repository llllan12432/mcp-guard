import sys

import pytest

from conftest import DEMO
from mcp_guard.config import load_config, load_policy


def test_demo_config_loads_and_resolves_paths():
    config = load_config(DEMO / "guard.yaml")
    assert set(config.servers) == {"notes", "notes_subtle", "mail"}
    assert config.servers["notes"].command == sys.executable  # "python" -> this interpreter
    assert config.servers["notes"].cwd == DEMO
    assert config.log_file == DEMO / "run" / "decisions.jsonl"
    assert config.detector == "rules"


def test_policy_patterns_are_globs_over_server_dot_tool():
    policy = load_policy(DEMO / "policy.yaml")
    assert policy.is_untrusted_source("notes.read_note") and policy.is_untrusted_source("notes_subtle.read_note")
    assert not policy.is_untrusted_source("mail.send_email")
    assert policy.is_high_risk("mail.send_email") and policy.is_high_risk("files.delete_file")
    assert not policy.is_high_risk("notes.read_note")


def test_invalid_policy_values_are_rejected(tmp_path):
    bad = tmp_path / "policy.yaml"
    bad.write_text("on_injected_result: maybe\n")
    with pytest.raises(ValueError):
        load_policy(bad)
