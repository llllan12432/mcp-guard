"""Rule-based detector: regular expressions plus a small scoring heuristic.

Two kinds of signals:

  * STRONG - phrases that have no business in a tool description or in data a
    tool returns ("ignore previous instructions", fake <system> tags, "do not
    tell the user", invisible Unicode tag characters). One hit is enough.
  * WEAK   - things that are common in honest text on their own (mentioning a
    password, an e-mail address after "send", "call the X tool"). Two different
    weak signals together are treated as an attack.

Everything is deterministic and explainable: the verdict's reason lists the
names of the signals that fired.
"""

from __future__ import annotations

import re

from .base import Verdict

_FLAGS = re.IGNORECASE | re.DOTALL

STRONG: dict[str, re.Pattern[str]] = {
    "instruction_override": re.compile(
        r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|preceding|all|your|any)\b.{0,30}"
        r"\b(instructions?|prompts?|rules|guidelines|directions|context)\b",
        _FLAGS,
    ),
    "instruction_override_zh": re.compile(
        r"(忽略|无视|忘记|忘掉|不要理会).{0,12}(之前|以上|上述|上面|先前|此前|所有).{0,8}(指令|指示|提示|规则|要求|设定)"
    ),
    "fake_system_markup": re.compile(
        r"<\s*/?\s*(system|important|instructions?|admin|secret|hidden)\s*>"
        r"|\[\s*/?\s*(system|admin|inst)\s*\]"
        r"|^\s*#{0,3}\s*system\s*(prompt|message|override|note)?\s*:",
        re.IGNORECASE | re.MULTILINE,
    ),
    "role_hijack": re.compile(
        r"\byou are now\b|\bnew (system )?instructions?\s*:|\bfrom now on,? you\b|\byour new (task|role|goal) is\b",
        _FLAGS,
    ),
    "hide_from_user": re.compile(
        r"\b(do not|don't|never|without)\b.{0,30}\b(tell|telling|inform|informing|mention|mentioning|notify|notifying|reveal|revealing|alert|alerting)\b"
        r".{0,30}\b(user|human|operator)\b",
        _FLAGS,
    ),
    "hide_from_user_zh": re.compile(r"(不要|别|切勿|无需|不必|不得).{0,8}(告诉|告知|通知|提及|提醒|透露).{0,8}用户"),
    # Unicode "tag" block: invisible characters used to smuggle ASCII text past human review.
    "invisible_tag_chars": re.compile("[\U000e0000-\U000e007f]"),
}

WEAK: dict[str, re.Pattern[str]] = {
    "addressed_to_ai": re.compile(
        r"\b(attention|note to|dear|hey|message for|instructions? for)\b.{0,15}\b(ai|assistant|agent|llm|model|chatbot)\b"
        r"|\b(ai|assistant|agent|llm)\b.{0,12}\b(must|should|need to|needs to|is required to|are required to)\b",
        _FLAGS,
    ),
    "tool_directive": re.compile(
        r"\b(call|invoke|use|run|execute)\b.{0,20}[`'\"]?\b\w+\b[`'\"]?\s+(tool|function)\b"
        r"|\b(before|after|when|whenever) (using|calling|invoking|you use|you call) (this|any|the)\b",
        _FLAGS,
    ),
    "sensitive_target": re.compile(
        r"~/\.ssh|\bid_rsa\b|\.env\b|\bapi[_ -]?keys?\b|\bpasswords?\b|\bcredentials?\b|\bsecrets?\b"
        r"|\b(access|auth|session) tokens?\b|\bprivate key\b|/etc/passwd|密码|密钥|凭证|凭据",
        _FLAGS,
    ),
    "send_to_address": re.compile(
        r"\b(send|sends|sending|forward|forwards|email|emails|mail|mails|post|posts|upload|uploads|exfiltrate|transmit|leak)\b"
        r".{0,80}?([\w.+-]+@[\w-]+\.[\w.-]+|https?://\S+)"
        r"|(发送|转发|上传|发到|发给|发往).{0,40}([\w.+-]+@[\w-]+\.[\w.-]+|https?://\S+)",
        _FLAGS,
    ),
    # Two or more zero-width characters: a common way to hide or split trigger words.
    "zero_width_chars": re.compile("[\u200b-\u200f\u2060-\u2064\ufeff].*[\u200b-\u200f\u2060-\u2064\ufeff]", re.DOTALL),
    "long_encoded_blob": re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"),
}

WEAK_SIGNALS_NEEDED = 2


class RulesDetector:
    name = "rules"

    async def check(self, text: str, surface: str) -> Verdict:
        strong = [name for name, pattern in STRONG.items() if pattern.search(text)]
        weak = [name for name, pattern in WEAK.items() if pattern.search(text)]
        if strong:
            return Verdict(True, "strong signal: " + ", ".join(strong + weak), self.name)
        if len(weak) >= WEAK_SIGNALS_NEEDED:
            return Verdict(True, "weak signals together: " + ", ".join(weak), self.name)
        if weak:
            return Verdict(False, "one weak signal only (not enough): " + weak[0], self.name)
        return Verdict(False, "no rule matched", self.name)
