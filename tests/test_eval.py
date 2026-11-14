import collections
import subprocess
import sys

import pytest

from conftest import ROOT

sys.path.insert(0, str(ROOT / "eval"))
import run_eval  # noqa: E402

from mcp_guard.config import load_policy  # noqa: E402
from mcp_guard.detectors.base import Verdict  # noqa: E402

pytestmark = pytest.mark.anyio

SAMPLES = run_eval.load_samples(ROOT / "eval" / "samples.jsonl")
POLICY = load_policy(ROOT / "eval" / "policy.yaml")


def test_seed_samples_are_well_formed():
    assert len({sample["id"] for sample in SAMPLES}) == len(SAMPLES)
    for sample in SAMPLES:
        assert {"id", "category", "surface", "malicious", "content", "note"} <= sample.keys()
        assert sample["surface"] in ("description", "result", "chain")
        assert sample["malicious"] == (sample["category"] != "benign")
    per_category = collections.Counter(sample["category"] for sample in SAMPLES)
    assert set(per_category) == {"description_poisoning", "result_injection", "exfil_chain", "benign"}
    assert all(count >= 5 for count in per_category.values())


async def test_none_detector_blocks_only_through_policy():
    result = await run_eval.evaluate("none", SAMPLES, POLICY)
    for row in result["rows"]:
        if row["sample"]["surface"] != "chain":
            assert not row["blocked"]
    assert any(row["blocked"] for row in result["rows"] if row["sample"]["category"] == "exfil_chain")


class Scripted:
    """Flags text containing ATTACK, errors on text containing BROKEN."""

    name = "scripted"

    async def check(self, text, surface):
        return Verdict("ATTACK" in text, "scripted", self.name, error="BROKEN" in text)


async def test_metrics_and_report_on_a_known_tiny_set(monkeypatch, tmp_path):
    samples = [
        {"id": "a", "category": "result_injection", "surface": "result", "malicious": True, "content": "ATTACK", "note": "caught"},
        {"id": "b", "category": "result_injection", "surface": "result", "malicious": True, "content": "quiet", "note": "missed one"},
        {"id": "c", "category": "benign", "surface": "result", "malicious": False, "content": "ATTACK quoted", "note": "false alarm"},
        {"id": "d", "category": "benign", "surface": "description", "malicious": False, "content": "fine", "note": "ok"},
        {"id": "e", "category": "benign", "surface": "result", "malicious": False, "content": "BROKEN", "note": "detector failed"},
    ]
    monkeypatch.setattr(run_eval, "build_detector", lambda name: Scripted())
    result = await run_eval.evaluate("scripted", samples, POLICY)
    assert [row["blocked"] for row in result["rows"]][:4] == [True, False, True, False]
    assert [row["error"] for row in result["rows"]] == [False, False, False, False, True]

    report = run_eval.render([result], ["llm"], samples, tmp_path / "tiny.jsonl")
    row = next(line for line in report.splitlines() if line.startswith("| `scripted`"))
    cells = [cell.strip() for cell in row.strip("|").split("|")]
    assert cells[2] == "1/2 (50%)"  # result injection block rate
    assert cells[4] == "1/2 (50%)"  # all malicious
    assert cells[5] == "1/2 (50%)"  # false positives: the errored sample is excluded
    assert cells[7] == "1"  # errors
    assert "- `b` (result_injection): missed one" in report
    assert "- `c` (result): false alarm" in report
    assert "| `llm` | skipped" in report and "No numbers are reported" in report


def test_script_runs_and_skips_llm_detectors_without_a_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    out = tmp_path / "results.md"
    run = subprocess.run([sys.executable, str(ROOT / "eval" / "run_eval.py"), "--out", str(out)], capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr
    report = out.read_text()
    assert "| `rules` |" in report and "| `none` |" in report
    assert "| `llm` | skipped" in report and "| `combined` | skipped" in report
    assert "## Missed attacks" in report and "## False positives" in report
