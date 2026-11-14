"""One-command demo:  python demo/run_demo.py

Runs the same simulated agent four times against the same fake servers:

  1. obvious attack, no proxy      -> the fake API key is e-mailed to the attacker
  2. obvious attack, through proxy -> poisoned tool removed, injected note withheld
  3. subtle attack, no proxy       -> the fake API key is e-mailed out again
  4. subtle attack, through proxy  -> the detector misses the note, but the action
                                      policy holds the e-mail for human approval

Everything is synthetic: fake notes, a fake key, and a "mail server" that only
appends to demo/run/outbox.jsonl. Exit code 0 means all four scenarios behaved
as described above.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import anyio
from mcp import StdioServerParameters

DEMO = Path(__file__).resolve().parent
sys.path.insert(0, str(DEMO))
sys.path.insert(0, str(DEMO.parent))

from agent import run_agent  # noqa: E402
from mcp_guard.config import load_config  # noqa: E402
from mcp_guard.session import SessionState  # noqa: E402

CONFIG = DEMO / "guard.yaml"
RUN = DEMO / "run"
OUTBOX = RUN / "outbox.jsonl"
LOG = RUN / "decisions.jsonl"


def direct(script: str, *args: str) -> StdioServerParameters:
    """The agent starts the server itself: no protection."""
    return StdioServerParameters(command=sys.executable, args=[str(DEMO / script), *args], cwd=DEMO)


def guarded(server: str) -> StdioServerParameters:
    """The agent starts the proxy, which starts the server named in guard.yaml."""
    args = ["-m", "mcp_guard", "run", "--config", str(CONFIG), "--server", server]
    return StdioServerParameters(command=sys.executable, args=args, cwd=DEMO.parent)


SCENARIOS = [
    # (title, notes server, mail server, should the data leak?)
    ("1. Obvious attack, NO proxy", direct("notes_server.py", "--variant", "obvious"), direct("mail_server.py"), True),
    ("2. Obvious attack, through MCP Guard", guarded("notes"), guarded("mail"), False),
    ("3. Subtle attack, NO proxy", direct("notes_server.py", "--variant", "subtle"), direct("mail_server.py"), True),
    ("4. Subtle attack, through MCP Guard", guarded("notes_subtle"), guarded("mail"), False),
]


def outbox() -> list[dict]:
    if not OUTBOX.exists():
        return []
    return [json.loads(line) for line in OUTBOX.read_text(encoding="utf-8").splitlines()]


def blocked_since(line_count: int) -> list[dict]:
    if not LOG.exists():
        return []
    records = [json.loads(line) for line in LOG.read_text(encoding="utf-8").splitlines()[line_count:]]
    return [record for record in records if record["verdict"] == "block"]


async def main() -> int:
    shutil.rmtree(RUN, ignore_errors=True)
    session = SessionState(load_config(CONFIG).session_file)
    summary = []

    for title, notes_server, mail_server, expect_leak in SCENARIOS:
        print(f"\n=== {title} ===")
        OUTBOX.unlink(missing_ok=True)
        session.reset()  # every scenario is a fresh agent session
        log_lines_before = len(LOG.read_text().splitlines()) if LOG.exists() else 0

        await run_agent(notes_server, mail_server)

        sent = outbox()
        leaked = any("FAKE-KEY" in mail["body"] for mail in sent)
        for mail in sent:
            print(f"  outbox: to={mail['to']} body={mail['body'][:60]!r}")
        for record in blocked_since(log_lines_before):
            print(f"  guard:  BLOCK {record['event']} {record['server']}.{record['tool']} [{record['detector']}] {record['reason']}")
        for call_id, call in session.pending().items():
            print(f"  guard:  waiting for human approval: {call_id} {call['tool']} to={call['arguments'].get('to')}")
        outcome = "ATTACK SUCCEEDED - fake key left the machine" if leaked else "attack stopped - nothing was sent"
        print(f"  result: {outcome}")
        summary.append((title, outcome, leaked == expect_leak))

    print("\n=== Summary ===")
    for title, outcome, as_expected in summary:
        print(f"  {title:<40} {outcome}{'' if as_expected else '   <-- UNEXPECTED'}")
    print(f"\nDecision log: {LOG.relative_to(DEMO.parent)}  (open viewer/index.html and load it)")
    return 0 if all(as_expected for _, _, as_expected in summary) else 1


if __name__ == "__main__":
    sys.exit(anyio.run(main))
