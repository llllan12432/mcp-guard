"""Unit tests for the decision engine, with a scripted detector and temp files."""

import json

import pytest

from mcp_guard.config import Policy
from mcp_guard.detectors.base import Verdict
from mcp_guard.guard import Guard, approval_id, collect_text
from mcp_guard.log import DecisionLog
from mcp_guard.session import SessionState

pytestmark = pytest.mark.anyio

POLICY = dict(untrusted_sources=["notes.*"], high_risk_tools=["mail.send_email", "*.delete_*"])


class KeywordDetector:
    """Malicious if the text contains EVIL; fails if it contains CRASH."""

    name = "keyword"

    async def check(self, text, surface):
        if "CRASH" in text:
            return Verdict(False, "detector error: boom", self.name, error=True)
        return Verdict("EVIL" in text, "contains EVIL" if "EVIL" in text else "clean", self.name)


@pytest.fixture
def make_guard(tmp_path):
    def make(server, **policy_overrides):
        policy = Policy(**{**POLICY, **policy_overrides})
        log = DecisionLog(tmp_path / "log.jsonl")
        return Guard(server, policy, KeywordDetector(), log, SessionState(tmp_path / "session.jsonl"))

    return make


def text_result(text):
    return {"content": [{"type": "text", "text": text}], "isError": False}


def test_collect_text_finds_nested_strings_and_skips_binary():
    tool = {
        "description": "top",
        "inputSchema": {"properties": {"q": {"type": "string", "description": "nested EVIL"}}},
        "icons": [{"data": "QUJDREVG"}],
    }
    text = collect_text(tool)
    assert "top" in text and "nested EVIL" in text and "QUJDREVG" not in text


def test_approval_id_depends_on_tool_and_arguments_only():
    assert approval_id("mail.send_email", {"a": 1, "b": 2}) == approval_id("mail.send_email", {"b": 2, "a": 1})
    assert approval_id("mail.send_email", {"a": 1}) != approval_id("mail.send_email", {"a": 2})


async def test_filter_tools_checks_parameter_docs_too(make_guard):
    guard = make_guard("notes")
    tools = [
        {"name": "ok", "description": "fine"},
        {"name": "bad_description", "description": "EVIL"},
        {"name": "bad_param", "description": "fine", "inputSchema": {"properties": {"q": {"description": "EVIL"}}}},
    ]
    assert [tool["name"] for tool in await guard.filter_tools(tools)] == ["ok"]
    assert await guard.check_call("bad_param", {}) is not None  # hidden tools cannot be called
    assert await guard.check_call("ok", {}) is None


async def test_hidden_tools_survive_a_second_page_of_the_listing(make_guard):
    guard = make_guard("notes")
    await guard.filter_tools([{"name": "bad", "description": "EVIL"}])  # page 1
    await guard.filter_tools([{"name": "ok", "description": "fine"}])  # page 2
    assert await guard.check_call("bad", {}) is not None


async def test_injected_result_is_replaced_and_taints(make_guard):
    guard = make_guard("web")  # "web.fetch" is not listed as untrusted
    assert guard.session.taint() is None
    replaced = await guard.check_result("fetch", text_result("EVIL payload"))
    assert replaced["isError"] and "EVIL payload" not in json.dumps(replaced)
    assert guard.session.taint()["source"] == "web.fetch"


async def test_injection_in_structured_content_is_found(make_guard):
    guard = make_guard("web")
    result = {"content": [{"type": "text", "text": "ok"}], "structuredContent": {"rows": [{"note": "EVIL"}]}}
    assert (await guard.check_result("fetch", result))["isError"]


async def test_clean_result_from_untrusted_source_passes_but_taints(make_guard):
    guard = make_guard("notes")
    original = text_result("just a note")
    assert await guard.check_result("read_note", original) is original
    assert guard.session.taint() is not None


async def test_clean_result_from_trusted_source_does_not_taint(make_guard):
    guard = make_guard("calendar")
    await guard.check_result("list_events", text_result("standup at 10"))
    assert guard.session.taint() is None


async def test_high_risk_call_held_only_after_taint_and_approval_is_single_use(make_guard):
    notes, mail = make_guard("notes"), make_guard("mail")  # two guards, one session file
    arguments = {"to": "x@example.com", "body": "hi"}
    assert await mail.check_call("send_email", arguments) is None  # clean session

    await notes.check_result("read_note", text_result("just a note"))
    message = await mail.check_call("send_email", arguments)
    call_id = approval_id("mail.send_email", arguments)
    assert message is not None and call_id in message
    assert list(mail.session.pending()) == [call_id]

    assert await notes.check_call("read_note", {"note_id": "n1"}) is None  # low-risk tools still work
    assert await notes.check_call("delete_note", {"note_id": "n1"}) is not None  # glob pattern "*.delete_*"

    assert mail.session.approve(call_id)
    assert await mail.check_call("send_email", arguments) is None
    assert await mail.check_call("send_email", arguments) is not None  # approval used up
    assert await mail.check_call("send_email", {**arguments, "to": "other@example.com"}) is not None


async def test_approving_one_call_does_not_approve_different_arguments(make_guard):
    notes, mail = make_guard("notes"), make_guard("mail")
    await notes.check_result("read_note", text_result("note"))
    await mail.check_call("send_email", {"to": "a@example.com"})
    assert mail.session.approve(approval_id("mail.send_email", {"to": "a@example.com"}))
    assert await mail.check_call("send_email", {"to": "attacker@evil.example"}) is not None


async def test_detector_error_fails_closed_by_default_and_open_if_configured(make_guard):
    closed = make_guard("web")
    assert (await closed.check_result("fetch", text_result("CRASH")))["isError"]
    assert await closed.filter_tools([{"name": "t", "description": "CRASH"}]) == []

    opened = make_guard("web", on_detector_error="allow")
    original = text_result("CRASH")
    assert await opened.check_result("fetch", original) is original


async def test_flag_mode_keeps_the_result(make_guard):
    guard = make_guard("web", on_injected_result="flag")
    original = text_result("EVIL payload")
    assert await guard.check_result("fetch", original) is original
    assert guard.session.taint() is not None


async def test_log_records_have_the_required_fields(make_guard):
    guard = make_guard("notes")
    await guard.filter_tools([{"name": "bad", "description": "EVIL"}])
    await guard.check_result("read_note", text_result("x"))
    await guard.check_call("read_note", {})
    records = [json.loads(line) for line in guard.log.path.read_text().splitlines()]
    assert [record["event"] for record in records] == ["tool_description", "tool_result", "tool_call"]
    for record in records:
        assert {"ts", "server", "tool", "detector", "verdict", "reason"} <= record.keys()
    assert records[0]["verdict"] == "block" and records[0]["detector"] == "keyword"


def test_session_state_is_shared_through_the_file(tmp_path):
    first, second = SessionState(tmp_path / "s.jsonl"), SessionState(tmp_path / "s.jsonl")
    assert second.taint() is None
    first.add_taint("notes.read_note", "why")
    assert second.taint()["source"] == "notes.read_note"
    assert not second.approve("nope") and not second.consume_approval("nope")
    first.reset()
    assert second.taint() is None
