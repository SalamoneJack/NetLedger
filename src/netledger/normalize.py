"""Configuration normalization: clean-up, volatile-line removal and secret masking."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable

from netledger.config import CustomRule, NormalizeSettings
from netledger.platforms import Platform, Rule, SecretRule

_ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])")
_CONTROL_RE = re.compile(r"[\x00\x07\x08\x0b\x0c]")
PLACEHOLDER_RE = re.compile(r"^<(?:removed|encrypted|secret:[0-9a-f]{6,64}|private key removed)>$")
MASK = "<removed>"


@dataclass
class NormalizeResult:
    text: str
    meta: dict[str, str] = field(default_factory=dict)


def basic_clean(text: str) -> str:
    """Normalize line endings, strip terminal escape codes and control characters."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _ANSI_RE.sub("", text)
    return _CONTROL_RE.sub("", text)


def finalize(text: str) -> str:
    """Strip trailing whitespace, surrounding blank lines and end with exactly one newline."""
    lines = [line.rstrip() for line in text.split("\n")]
    body = "\n".join(lines).strip("\n")
    return body + "\n" if body else ""


def extract_meta(text: str, patterns: Iterable[re.Pattern[str]]) -> dict[str, str]:
    meta: dict[str, str] = {}
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            meta.update({k: v.strip() for k, v in match.groupdict().items() if v})
    return meta


def apply_rules(text: str, rules: Iterable[Rule], disabled: set[str] = frozenset()) -> str:
    rules = [r for r in rules if r.id not in disabled]
    drops = [r.regex for r in rules if r.replace is None]
    if drops:
        text = "\n".join(line for line in text.split("\n") if not any(rx.search(line) for rx in drops))
    for rule in rules:
        if rule.replace is not None:
            text = rule.regex.sub(rule.replace, text)
    return text


def _replace_secret(match: re.Match[str], replacer: Callable[[str], str]) -> str:
    value = match.group("secret")
    if value is None:
        return match.group(0)
    quote = ""
    inner = value
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        quote, inner = value[0], value[1:-1]
    if PLACEHOLDER_RE.match(inner) or not inner:
        return match.group(0)
    start, end = match.span("secret")
    offset = match.start()
    whole = match.group(0)
    return whole[: start - offset] + f"{quote}{replacer(inner)}{quote}" + whole[end - offset :]


def apply_secret_rules(
    text: str,
    rules: Iterable[SecretRule],
    replacer: Callable[[str], str],
    disabled: set[str] = frozenset(),
) -> str:
    for rule in rules:
        if rule.id in disabled:
            continue
        text = rule.regex.sub(lambda m: _replace_secret(m, replacer), text)
    return text


class Normalizer:
    """Applies the normalization pipeline for a platform according to user settings."""

    def __init__(self, settings: NormalizeSettings | None = None):
        settings = settings or NormalizeSettings()
        self.mode = settings.secrets
        self._key = (settings.secret_key or "").encode()
        self.disabled = set(settings.disable_rules)
        self.custom = [self._compile(rule) for rule in settings.rules]

    @staticmethod
    def _compile(rule: CustomRule) -> tuple[re.Pattern[str], str | None, set[str]]:
        flags = re.M | (re.S if rule.multiline else 0)
        platforms = {p.lower() for p in rule.platforms}
        return re.compile(rule.pattern, flags), rule.replace, platforms

    def _custom_for(self, platform: Platform) -> list[tuple[re.Pattern[str], str | None]]:
        result = []
        for regex, replace, platforms in self.custom:
            if not platforms or platform.key.lower() in platforms:
                result.append((regex, replace))
        return result

    def _hmac(self, value: str) -> str:
        digest = hmac.new(self._key, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()
        return f"<secret:{digest[:12]}>"

    def replacer(self, mode: str | None = None) -> Callable[[str], str] | None:
        mode = mode or self.mode
        if mode == "mask":
            return lambda _value: MASK
        if mode == "hmac":
            return self._hmac
        return None

    def normalize(self, text: str, platform: Platform, secrets: str | None = None) -> NormalizeResult:
        """Full pipeline. ``secrets`` overrides the configured mode (keep/mask/hmac)."""
        text = basic_clean(text)
        meta = extract_meta(text, platform.meta_regexes)
        text = apply_rules(text, platform.volatile, self.disabled)
        for regex, replace in self._custom_for(platform):
            if replace is None:
                text = "\n".join(line for line in text.split("\n") if not regex.search(line))
            else:
                text = regex.sub(replace, text)
        replacer = self.replacer(secrets)
        if replacer is not None:
            text = apply_secret_rules(text, platform.secrets, replacer, self.disabled)
        return NormalizeResult(finalize(text), meta)

    def normalize_output(self, text: str, platform: Platform, exclude: Iterable[str] = ()) -> str:
        """Normalize extra command output: drop excluded lines and handle secrets like configs."""
        text = basic_clean(text)
        patterns = [re.compile(p) for p in exclude]
        if patterns:
            text = "\n".join(line for line in text.split("\n") if not any(p.search(line) for p in patterns))
        replacer = self.replacer()
        if replacer is not None:
            text = apply_secret_rules(text, platform.secrets, replacer, self.disabled)
        return finalize(text)

    def mask(self, text: str | None, platform: Platform) -> str | None:
        """Always-masked copy of already-normalized text (used for notifications and the dashboard)."""
        if text is None:
            return None
        return apply_secret_rules(text, platform.secrets, lambda _v: MASK, self.disabled)
