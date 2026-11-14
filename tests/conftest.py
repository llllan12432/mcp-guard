import sys
from pathlib import Path

import pytest
import yaml
from mcp import StdioServerParameters

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "demo"
FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def guard_config(tmp_path):
    """Write a proxy config in a temp dir that wraps the demo servers.

    Returns a helper object with the config path and the runtime file locations,
    so every test gets its own log, session and outbox.
    """

    class Paths:
        config = tmp_path / "guard.yaml"
        log = tmp_path / "decisions.jsonl"
        session = tmp_path / "session.jsonl"
        outbox = tmp_path / "outbox.jsonl"

        @staticmethod
        def proxied(server: str) -> StdioServerParameters:
            args = ["-m", "mcp_guard", "run", "--config", str(Paths.config), "--server", server]
            return StdioServerParameters(command=sys.executable, args=args)

    def write(detector: str = "rules", **policy_overrides):
        policy = yaml.safe_load((DEMO / "policy.yaml").read_text())
        policy.update(policy_overrides)
        (tmp_path / "policy.yaml").write_text(yaml.safe_dump(policy))
        Paths.config.write_text(yaml.safe_dump({
            "detector": detector,
            "policy_file": "policy.yaml",
            "log_file": str(Paths.log),
            "session_file": str(Paths.session),
            "servers": {
                "notes": {"command": "python", "args": [str(DEMO / "notes_server.py"), "--variant", "obvious"]},
                "notes_subtle": {"command": "python", "args": [str(DEMO / "notes_server.py"), "--variant", "subtle"]},
                "mail": {"command": "python", "args": [str(DEMO / "mail_server.py"), "--outbox", str(Paths.outbox)]},
                "echo": {"command": "python", "args": [str(FIXTURES / "echo_server.py")]},
            },
        }))
        return Paths

    return write
