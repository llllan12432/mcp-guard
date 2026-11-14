"""The decision engine: detectors + policy + session state + logging.

`Guard` has no knowledge of transports or JSON-RPC. The proxy calls its three
methods at the three inspection points; the evaluation harness and unit tests
call the same methods directly. One Guard wraps one downstream server.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from .config import Policy
from .detectors.base import Detector, Verdict
from .log import DecisionLog
from .session import SessionState


def blocked_result(reason: str) -> dict[str, Any]:
    """A tools/call result telling the agent that the guard stepped in.

    It is a normal tool result with isError=true (not a JSON-RPC error), which
    is how MCP says tool-level failures should be reported so the model sees them.
    """
    return {
        "content": [{"type": "text", "text": f"[MCP Guard] {reason}"}],
        "isError": True,
        "resultType": "complete",  # required by protocol 2026-07-28; ignored by older clients
    }


def collect_text(value: Any) -> str:
    """Every string inside a JSON value, joined by newlines.

    Used for both tool definitions and tool results, so hidden instructions are
    found wherever they sit (description, parameter docs, structuredContent...).
    Binary payloads (base64 image/audio/blob data) are skipped.
    """
    parts: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, str):
            if node not in parts:  # structuredContent usually repeats the text block
                parts.append(node)
        elif isinstance(node, dict):
            for key, child in node.items():
                if key not in ("data", "blob"):
                    walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    return "\n".join(parts)


def approval_id(qualified_tool: str, arguments: dict[str, Any]) -> str:
    """Stable short id for one exact call: same tool + same arguments -> same id."""
    canonical = json.dumps([qualified_tool, arguments], sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:8]


class Guard:
    def __init__(self, server: str, policy: Policy, detector: Detector, log: DecisionLog, session: SessionState):
        self.server = server
        self.policy = policy
        self.detector = detector
        self.log = log
        self.session = session
        self.hidden_tools: set[str] = set()  # tools removed from tools/list

    # -- helpers ---------------------------------------------------------

    async def _detect(self, text: str, surface: str) -> tuple[Verdict, float]:
        start = time.perf_counter()
        verdict = await self.detector.check(text, surface)
        return verdict, round((time.perf_counter() - start) * 1000, 2)

    def _should_block(self, verdict: Verdict) -> bool:
        if verdict.error:
            return self.policy.on_detector_error == "block"
        return verdict.malicious

    # -- inspection point 1: tools/list response -------------------------

    async def filter_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Drop every tool whose definition looks poisoned."""
        kept = []
        for tool in tools:
            name = str(tool.get("name", ""))
            # Check everything except the name: description, title, parameter docs, annotations.
            definition = {key: value for key, value in tool.items() if key != "name"}
            verdict, ms = await self._detect(collect_text(definition), "description")
            block = self._should_block(verdict)
            if block:
                self.hidden_tools.add(name)
            else:
                self.hidden_tools.discard(name)  # a later, clean listing un-hides it
                kept.append(tool)
            self.log.write(
                server=self.server, event="tool_description", tool=name, detector=verdict.detector,
                verdict="block" if block else "allow", reason=verdict.reason, latency_ms=ms,
            )
        return kept

    # -- inspection point 2: tools/call request --------------------------

    async def check_call(self, tool: str, arguments: dict[str, Any]) -> str | None:
        """Return None to forward the call, or a message explaining why it is blocked."""
        qualified = f"{self.server}.{tool}"

        if tool in self.hidden_tools:
            reason = "tool was removed from the tool list (poisoned description)"
            self.log.write(server=self.server, event="tool_call", tool=tool, detector="policy", verdict="block", reason=reason)
            return f"Tool '{tool}' is not available: its description was flagged as tool poisoning."

        taint = self.session.taint()
        if self.policy.is_high_risk(qualified) and taint is not None:
            call_id = approval_id(qualified, arguments)
            if self.session.consume_approval(call_id):
                reason = f"high-risk call after untrusted content, approved by a human (id {call_id})"
                self.log.write(server=self.server, event="tool_call", tool=tool, detector="policy", verdict="allow", reason=reason, approval_id=call_id)
                return None
            self.session.add_pending(call_id, qualified, arguments)
            reason = f"high-risk tool called after the session read untrusted content ({taint['source']}: {taint['reason']})"
            self.log.write(server=self.server, event="tool_call", tool=tool, detector="policy", verdict="block", reason=reason, approval_id=call_id, arguments=arguments)
            # The approval id is deliberately NOT in this message: the agent has no need
            # for it. The human finds it with `mcp-guard pending` or in the decision log.
            return (
                f"Call to high-risk tool '{tool}' is on hold: this session has read untrusted content, "
                "so a human must approve it first. Tell the user; do not retry until they have approved it."
            )

        self.log.write(server=self.server, event="tool_call", tool=tool, detector="policy", verdict="allow", reason="no policy rule applies")
        return None

    # -- inspection point 3: tools/call response -------------------------

    async def check_result(self, tool: str, result: dict[str, Any]) -> dict[str, Any]:
        """Return the result to hand to the agent (the original or a replacement)."""
        qualified = f"{self.server}.{tool}"
        if self.policy.is_untrusted_source(qualified):
            self.session.add_taint(qualified, "result of a tool listed under untrusted_sources")

        verdict, ms = await self._detect(collect_text(result), "result")
        flagged = self._should_block(verdict)
        if flagged:
            self.session.add_taint(qualified, f"detector {verdict.detector} flagged the result")
        block = flagged and self.policy.on_injected_result == "block"
        self.log.write(
            server=self.server, event="tool_result", tool=tool, detector=verdict.detector,
            verdict="block" if block else ("flag" if flagged else "allow"), reason=verdict.reason, latency_ms=ms,
        )
        if block:
            return blocked_result(f"The result of '{tool}' was withheld: it looks like a prompt injection ({verdict.reason}).")
        return result
