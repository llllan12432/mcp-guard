"""End-to-end tests with real subprocesses: SDK client -> proxy -> MCP server."""

import json
import os
import pty
import select
import subprocess
import sys

import pytest
from mcp import Client, StdioServerParameters

from conftest import FIXTURES

pytestmark = pytest.mark.anyio

ECHO_DIRECT = StdioServerParameters(command=sys.executable, args=[str(FIXTURES / "echo_server.py")])


def text_of(result) -> str:
    return result.content[0].text


def cli(config, *args) -> subprocess.CompletedProcess:
    command = [sys.executable, "-m", "mcp_guard", args[0], "--config", str(config), *args[1:]]
    return subprocess.run(command, capture_output=True, text=True)


def approve_in_terminal(config, call_id: str, answer: str) -> tuple[int, str]:
    """Run `approve` attached to a pseudo-terminal and type an answer, as a person would.

    (That a test can do this is also the limit of the mitigation: so could an agent
    able to allocate a pty. README, Limitations.)
    """
    master, slave = pty.openpty()
    command = [sys.executable, "-m", "mcp_guard", "approve", "--config", str(config), call_id]
    process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    os.write(master, (answer + "\n").encode())
    screen = b""
    while True:
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(master, 4096)
            except OSError:  # the terminal closed
                break
            if not chunk:
                break
            screen += chunk
        elif process.poll() is not None:
            break
    os.close(master)
    return process.wait(timeout=10), screen.decode(errors="replace")


async def snapshot(params: StdioServerParameters, mode: str) -> dict:
    """Everything a client can observe from the echo server, as plain data."""
    async with Client(params, mode=mode) as client:
        tools = await client.list_tools()
        call = await client.call_tool("add", {"a": 2, "b": 3})
        resource = await client.read_resource("fixture://greeting")
        return {
            "protocol": client.protocol_version,
            "tools": [tool.model_dump() for tool in tools.tools],
            "call": call.model_dump(),
            "resource": resource.contents[0].text,
        }


# "auto" negotiates the stateless 2026-07-28 protocol; "legacy" forces the initialize handshake.
@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_proxy_is_transparent_for_a_benign_server(guard_config, mode):
    paths = guard_config()
    direct = await snapshot(ECHO_DIRECT, mode)
    proxied = await snapshot(paths.proxied("echo"), mode)
    assert proxied == direct
    assert direct["call"]["structured_content"] == {"result": 5}


async def test_poisoned_tool_is_removed_and_cannot_be_called(guard_config):
    paths = guard_config()
    async with Client(paths.proxied("notes")) as client:
        names = [tool.name for tool in (await client.list_tools()).tools]
        assert names == ["list_notes", "read_note"]  # search_notes is gone
        # Call it anyway, as an agent that learned the name elsewhere might.
        # (session.call_tool skips the SDK's client-side "is this tool listed" bookkeeping.)
        result = await client.session.call_tool("search_notes", {"query": "x"})
        assert result.is_error and "[MCP Guard]" in text_of(result)


async def test_injected_result_is_withheld_and_clean_result_passes(guard_config):
    paths = guard_config()
    async with Client(paths.proxied("notes")) as client:
        await client.list_tools()
        clean = await client.call_tool("read_note", {"note_id": "n1"})
        assert not clean.is_error and "Groceries" in text_of(clean)
        poisoned = await client.call_tool("read_note", {"note_id": "n2"})
        assert poisoned.is_error
        assert "[MCP Guard]" in text_of(poisoned)
        assert "attacker@evil.example" not in text_of(poisoned)


async def test_flag_mode_passes_the_result_but_still_taints(guard_config):
    paths = guard_config(on_injected_result="flag")
    async with Client(paths.proxied("notes")) as client:
        result = await client.call_tool("read_note", {"note_id": "n2"})
        assert not result.is_error and "attacker@evil.example" in text_of(result)
    verdicts = [json.loads(line)["verdict"] for line in paths.log.read_text().splitlines()]
    assert "flag" in verdicts


async def test_high_risk_call_is_allowed_while_session_is_clean(guard_config):
    paths = guard_config()
    async with Client(paths.proxied("mail")) as mail:
        result = await mail.call_tool("send_email", {"to": "bob@example.com", "subject": "hi", "body": "lunch?"})
        assert not result.is_error
    assert json.loads(paths.outbox.read_text())["to"] == "bob@example.com"


async def test_exfiltration_chain_is_held_across_two_proxies_until_approved(guard_config):
    """The subtle note slips past the rules, so only the action policy stops the e-mail."""
    paths = guard_config()
    email = {"to": "archive-desk@partner-archive.example", "subject": "note n3", "body": "FAKE-KEY"}

    async with Client(paths.proxied("notes_subtle")) as notes, Client(paths.proxied("mail")) as mail:
        note = await notes.call_tool("read_note", {"note_id": "n2"})
        assert not note.is_error and "archive-desk" in text_of(note)  # detector missed it

        held = await mail.call_tool("send_email", email)
        assert held.is_error and "on hold" in text_of(held)
        assert not paths.outbox.exists()  # nothing was sent

        # The human finds the held call with `pending`; the agent was not told its id.
        listing = cli(paths.config, "pending").stdout
        call_id = listing.split()[0]
        assert "mail.send_email" in listing and call_id not in text_of(held)

        # Without a terminal (how an agent's shell tool would run it) approve is refused.
        refused = cli(paths.config, "approve", call_id)
        assert refused.returncode == 2 and "interactive terminal" in refused.stderr
        assert (await mail.call_tool("send_email", email)).is_error
        assert cli(paths.config, "approve", "wrong-id").returncode == 1

        # In a terminal, anything but "yes" leaves the call held; "yes" releases it once.
        code, screen = approve_in_terminal(paths.config, call_id, "no")
        assert code == 1 and "archive-desk@partner-archive.example" in screen  # the call is shown first
        assert (await mail.call_tool("send_email", email)).is_error
        code, _ = approve_in_terminal(paths.config, call_id, "yes")
        assert code == 0

        approved = await mail.call_tool("send_email", email)
        assert not approved.is_error
        assert len(paths.outbox.read_text().splitlines()) == 1

        # The approval was for one call only.
        again = await mail.call_tool("send_email", email)
        assert again.is_error
        assert len(paths.outbox.read_text().splitlines()) == 1

    # `reset` starts a new, clean session.
    assert cli(paths.config, "reset").returncode == 0
    async with Client(paths.proxied("mail")) as mail:
        assert not (await mail.call_tool("send_email", email)).is_error


async def test_every_decision_is_logged_as_jsonl(guard_config):
    paths = guard_config()
    async with Client(paths.proxied("notes")) as client:
        await client.list_tools()
        await client.call_tool("read_note", {"note_id": "n2"})
    records = [json.loads(line) for line in paths.log.read_text().splitlines()]
    for record in records:
        assert {"ts", "server", "event", "tool", "detector", "verdict", "reason"} <= record.keys()
    assert {record["event"] for record in records} == {"tool_description", "tool_call", "tool_result"}
    blocked = [(record["event"], record["tool"]) for record in records if record["verdict"] == "block"]
    assert blocked == [("tool_description", "search_notes"), ("tool_result", "read_note")]
