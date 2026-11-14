"""Load the proxy config file and the policy file (both YAML).

Config file (which servers to wrap, where to write files):

    detector: rules              # none | rules | llm | combined
    policy_file: policy.yaml
    log_file: run/decisions.jsonl
    session_file: run/session.jsonl
    servers:
      notes:
        command: python
        args: [notes_server.py]

Policy file (what counts as untrusted / high risk):

    untrusted_sources: ["notes.*"]        # "<server>.<tool>" glob patterns
    high_risk_tools:   ["mail.send_email"]
    on_injected_result: block             # block | flag
    on_detector_error: block              # block | allow

Relative paths are resolved against the directory of the config file, so the
proxy behaves the same no matter which directory the agent host starts it from.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

import yaml


@dataclass
class ServerConfig:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: Path | None = None


@dataclass
class Policy:
    untrusted_sources: list[str] = field(default_factory=list)
    high_risk_tools: list[str] = field(default_factory=list)
    on_injected_result: str = "block"  # "block": withhold the result; "flag": pass it on, only taint + log
    on_detector_error: str = "block"  # what to do when a detector itself fails

    def is_untrusted_source(self, qualified_tool: str) -> bool:
        return _matches(qualified_tool, self.untrusted_sources)

    def is_high_risk(self, qualified_tool: str) -> bool:
        return _matches(qualified_tool, self.high_risk_tools)


@dataclass
class Config:
    servers: dict[str, ServerConfig]
    policy: Policy
    detector: str
    log_file: Path
    session_file: Path


def _matches(qualified_tool: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(qualified_tool, pattern) for pattern in patterns)


def load_policy(path: str | Path) -> Policy:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    policy = Policy(
        untrusted_sources=list(data.get("untrusted_sources", [])),
        high_risk_tools=list(data.get("high_risk_tools", [])),
        on_injected_result=data.get("on_injected_result", "block"),
        on_detector_error=data.get("on_detector_error", "block"),
    )
    if policy.on_injected_result not in ("block", "flag"):
        raise ValueError("policy: on_injected_result must be 'block' or 'flag'")
    if policy.on_detector_error not in ("block", "allow"):
        raise ValueError("policy: on_detector_error must be 'block' or 'allow'")
    return policy


def load_config(path: str | Path) -> Config:
    path = Path(path).resolve()
    base = path.parent
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    servers: dict[str, ServerConfig] = {}
    for name, spec in (data.get("servers") or {}).items():
        command = spec["command"]
        if command == "python":
            # Use the interpreter running the proxy, so the wrapped server sees
            # the same virtualenv even when the host's PATH does not include it.
            command = sys.executable
        servers[name] = ServerConfig(
            name=name,
            command=command,
            args=[str(arg) for arg in spec.get("args", [])],
            env={key: str(value) for key, value in (spec.get("env") or {}).items()},
            cwd=(base / spec["cwd"]) if spec.get("cwd") else base,
        )
    if not servers:
        raise ValueError(f"{path}: no servers configured")

    return Config(
        servers=servers,
        policy=load_policy(base / data.get("policy_file", "policy.yaml")),
        detector=data.get("detector", "rules"),
        log_file=base / data.get("log_file", "logs/decisions.jsonl"),
        session_file=base / data.get("session_file", "logs/session.jsonl"),
    )
