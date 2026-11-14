"""Fake mail MCP server. `send_email` sends nothing: it appends the message to a local
JSONL file (the "outbox"), which is how the demo checks whether an attack succeeded.

    python mail_server.py --outbox run/outbox.jsonl
"""

import argparse
import json
from pathlib import Path

from mcp.server import MCPServer


def build_server(outbox: Path) -> MCPServer:
    server = MCPServer("mail")

    @server.tool()
    def send_email(to: str, subject: str, body: str) -> str:
        """Send an e-mail. (Demo: the message is only written to a local file.)"""
        outbox.parent.mkdir(parents=True, exist_ok=True)
        with outbox.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"to": to, "subject": subject, "body": body}) + "\n")
        return f"email to {to} sent"

    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--outbox", default="run/outbox.jsonl")
    build_server(Path(parser.parse_args().outbox)).run("stdio")
