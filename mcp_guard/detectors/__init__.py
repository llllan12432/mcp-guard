"""Pluggable detectors. `build_detector(name)` is the only place that knows the list."""

from __future__ import annotations

from .base import Detector, NoneDetector, Verdict
from .combined import CombinedDetector
from .llm import LLMDetector
from .rules import RulesDetector

DETECTOR_NAMES = ("none", "rules", "llm", "combined")


def build_detector(name: str) -> Detector:
    if name == "none":
        return NoneDetector()
    if name == "rules":
        return RulesDetector()
    if name == "llm":
        return LLMDetector()
    if name == "combined":
        return CombinedDetector(RulesDetector(), LLMDetector())
    raise ValueError(f"unknown detector '{name}' (choose from {', '.join(DETECTOR_NAMES)})")


__all__ = ["Detector", "Verdict", "NoneDetector", "RulesDetector", "LLMDetector", "CombinedDetector", "build_detector", "DETECTOR_NAMES"]
