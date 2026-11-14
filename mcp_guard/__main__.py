"""Command line entry point.

    python -m mcp_guard run     --config guard.yaml --server notes   # start a proxy (used by the agent host)
    python -m mcp_guard pending --config guard.yaml                  # list calls waiting for approval
    python -m mcp_guard approve --config guard.yaml <id>             # approve one held call (once)
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
        if not session.approve(args.id):
            print(f"no held call with id {args.id}", file=sys.stderr)
            return 1
        print(f"approved {args.id}: the agent may now repeat this exact call once")
    elif args.command == "reset":
        session.reset()
        print("session state cleared")
    return 0


if __name__ == "__main__":
    sys.exit(main())
