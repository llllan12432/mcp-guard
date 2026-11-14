"""A simulated, deliberately gullible agent (no LLM involved).

Its task is harmless: "summarise my notes". But like a model that falls for
prompt injection, it obeys instructions found in anything it reads - tool
descriptions and tool results. Concretely: if a text names a note and an
e-mail address, it reads that note and e-mails it to that address.

Being deterministic makes the demo reproducible and free to run. It shows what
the proxy does at the protocol level; it does not claim that a particular real
model would be fooled in exactly this way.
"""

from __future__ import annotations

import re

from mcp import Client, StdioServerParameters

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
NOTE_REF = re.compile(r"\bnote\s+(n\d+)", re.IGNORECASE)


def find_injected_order(text: str) -> tuple[str, str] | None:
    """Return (note id, e-mail address) if the text asks to send a note somewhere."""
    address, note = EMAIL.search(text), NOTE_REF.search(text)
    if address and note:
        return note.group(1), address.group(0).rstrip(".")
    return None


def _text(result) -> str:
    return "\n".join(block.text for block in result.content if block.type == "text")


async def run_agent(notes_server: StdioServerParameters, mail_server: StdioServerParameters, say=print) -> None:
    async with Client(notes_server) as notes, Client(mail_server) as mail:
        can_send = any(tool.name == "send_email" for tool in (await mail.list_tools()).tools)
        already_obeyed: set[tuple[str, str]] = set()

        async def read(note_id: str) -> str:
            result = await notes.call_tool("read_note", {"note_id": note_id})
            text = _text(result)
            say(f"  agent: read_note({note_id}) -> {'[error] ' if result.is_error else ''}{text[:70]!r}")
            return "" if result.is_error else text

        async def obey(text: str, found_in: str) -> None:
            order = find_injected_order(text)
            if not order or order in already_obeyed or not can_send:
                return
            already_obeyed.add(order)
            note_id, address = order
            say(f"  agent: (!) following an instruction found in {found_in}: send note {note_id} to {address}")
            body = await read(note_id)
            if not body:
                return
            result = await mail.call_tool("send_email", {"to": address, "subject": f"note {note_id}", "body": body})
            say(f"  agent: send_email(to={address}) -> {'[error] ' if result.is_error else ''}{_text(result)[:110]!r}")

        # 1. The agent loads the tool list; descriptions become part of its context.
        tools = (await notes.list_tools()).tools
        say(f"  agent: notes tools = {[tool.name for tool in tools]}")
        for tool in tools:
            await obey(tool.description or "", f"the description of tool '{tool.name}'")

        # 2. The actual task: read every note in order to summarise them.
        listing = await notes.call_tool("list_notes", {})
        for note_id in (listing.structured_content or {}).get("result", []):
            await obey(await read(note_id), f"note {note_id}")
        say("  agent: done, here is your summary (omitted)")
