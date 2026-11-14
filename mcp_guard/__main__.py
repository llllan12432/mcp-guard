"""Command line entry point.

    python -m mcp_guard run     --config guard.yaml --server notes   # start a proxy (used by the agent host)
    python -m mcp_guard pending --config guard.yaml                  # list calls waiting for approval
    python -m mcp_guard approve --config guard.yaml <id>             # approve one held call (once); asks for
                                                                     # confirmation, interactive terminal only
    python -m mcp_guard reset   --config guard.yaml                  # start a new session (clears taint)
"""

from __future__ import annotations

import argparse
import json
import sys

import anyio

from .config import load_config
from .detectors import build_detector
from .guard import Guard
from .log import DecisionLog
from .proxy import run_proxy
from .session import SessionState


def approve_interactively(session: SessionState, call_id: str) -> int:
    """Approve one held call, but only for a person at a terminal who types "yes".

    Refusing to run without a terminal stops the simplest self-approval: an agent
    running this command through an ordinary (non-interactive) shell tool. It is a
    speed bump, not a boundary: an agent that can allocate a pseudo-terminal, or
    write to the session file directly, still gets through. See README, Limitations.
    """
    call = session.pending().get(call_id)
    if call is None:
        print(f"no held call with id {call_id}", file=sys.stderr)
        return 1
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("refused: 'approve' must be run by a person in an interactive terminal", file=sys.stderr)
        return 2
    print("Held call:")
    print(f"  tool:      {call['tool']}")
    print(f"  arguments: {json.dumps(call['arguments'], ensure_ascii=False)}")
    if input('Type "yes" to allow this exact call once: ').strip().lower() != "yes":
        print("not approved")
        return 1
    session.approve(call_id)
    print(f"approved {call_id}: the agent may now repeat this exact call once")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-guard", description="Firewall proxy for MCP tool calls")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "pending", "approve", "reset"):
        sub = commands.add_parser(name)
        sub.add_argument("--config", required=True, help="path to the proxy config YAML")
        if name == "run":
            sub.add_argument("--server", required=True, help="name of the server (from the config) to wrap")
        if name == "approve":
            sub.add_argument("id", help="approval id shown in the log and by 'pending'")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    session = SessionState(config.session_file)

    if args.command == "run":
        if args.server not in config.servers:
            parser.error(f"server '{args.server}' is not in {args.config} (have: {', '.join(config.servers)})")
        guard = Guard(args.server, config.policy, build_detector(config.detector), DecisionLog(config.log_file), session)
        anyio.run(run_proxy, config.servers[args.server], guard)
    elif args.command == "pending":
        for call_id, call in session.pending().items():
            print(f"{call_id}  {call['tool']}  {json.dumps(call['arguments'], ensure_ascii=False)}")
    elif args.command == "approve":
        return approve_interactively(session, args.id)
    elif args.command == "reset":
        session.reset()
        print("session state cleared")
    return 0


if __name__ == "__main__":
    sys.exit(main())
