"""Rules first, LLM second.

The rules run in microseconds and cost nothing, so a rule hit is final and the
LLM is not called. Only text the rules consider clean is sent to the LLM, which
catches paraphrased attacks the patterns miss. The result is the OR of the two:
higher recall than either, at the cost of also inheriting both false-positive sets.
"""

from __future__ import annotations

from .base import Detector, Verdict


class CombinedDetector:
    name = "combined"

    def __init__(self, rules: Detector, llm: Detector):
        self.rules = rules
        self.llm = llm

    async def check(self, text: str, surface: str) -> Verdict:
        first = await self.rules.check(text, surface)
        if first.malicious:
            return Verdict(True, f"rules: {first.reason}", self.name)
        second = await self.llm.check(text, surface)
        return Verdict(second.malicious, f"llm: {second.reason}", self.name, error=second.error)
