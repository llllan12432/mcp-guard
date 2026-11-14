"""The detector interface. A detector answers one question about one piece of text:
does it contain instructions aimed at the AI agent that reads it?"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Verdict:
    malicious: bool
    reason: str
    detector: str
    error: bool = False  # the detector itself failed; policy decides what that means


class Detector(Protocol):
    name: str

    async def check(self, text: str, surface: str) -> Verdict:
        """`surface` is "description" (a tool definition) or "result" (a tool's output)."""
        ...


class NoneDetector:
    """Flags nothing. Baseline that shows what the action policy does on its own."""

    name = "none"

    async def check(self, text: str, surface: str) -> Verdict:
        return Verdict(False, "no detector configured", self.name)
