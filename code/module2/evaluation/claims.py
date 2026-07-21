"""Claim extraction and validation for Module 3 evaluation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Sequence

from ..generation.llm_client import LLMClient
from ..generation.pipeline import REPORT_SECTIONS

_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "claim_extraction.md"
_CLAIM_TYPES = ("feature", "knowledge", "procedural")
_REF_PATTERN = re.compile(r"\[(?:E|C)\d+\]", re.IGNORECASE)
_FEATURE_PATTERN = re.compile(r"\b[A-Z]+_\w+\b")
_HEADING_PATTERN = re.compile(r"^##\s+(.+?)\s*$")
_LIST_PREFIX_PATTERN = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)")

_HEADING_TO_SECTION = {
    section.replace("_", " ").replace("longer term", "longer-term"): section
    for section in REPORT_SECTIONS
}


class EvalParseError(ValueError):
    """Raised when an evaluator LLM response violates the frozen schema."""


@dataclass(slots=True)
class Claim:
    text: str
    section: str
    type: str
    cited_refs: list[str]
    label: str | None = None


def _claim_from_object(item: Any, index: int) -> Claim:
    if not isinstance(item, dict):
        raise EvalParseError(f"claim {index}: expected an object, got {type(item).__name__}")
    try:
        text = item["text"]
        section = item["section"]
        claim_type = item["type"]
        cited_refs = item["cited_refs"]
    except KeyError as exc:
        raise EvalParseError(f"claim {index}: missing field {exc.args[0]!r}") from exc

    if not isinstance(text, str) or not text.strip():
        raise EvalParseError(f"claim {index}: text must be a non-empty string")
    if section not in REPORT_SECTIONS:
        raise EvalParseError(
            f"claim {index}: invalid section {section!r}; expected one of {REPORT_SECTIONS}"
        )
    if claim_type not in _CLAIM_TYPES:
        raise EvalParseError(
            f"claim {index}: invalid type {claim_type!r}; expected one of {_CLAIM_TYPES}"
        )
    if not isinstance(cited_refs, list) or not all(
        isinstance(ref, str) for ref in cited_refs
    ):
        raise EvalParseError(f"claim {index}: cited_refs must be a list of strings")
    label = item.get("label")
    if label is not None and not isinstance(label, str):
        raise EvalParseError(f"claim {index}: label must be a string or null")
    return Claim(text, section, claim_type, list(cited_refs), label)


def parse_claims_json(raw: str) -> list[Claim]:
    """Parse and validate the claim extractor's JSON-array response."""

    try:
        value = json.loads(raw.strip())
    except (json.JSONDecodeError, TypeError) as exc:
        detail = getattr(exc, "msg", str(exc))
        raise EvalParseError(f"claim extraction JSON is invalid: {detail}") from exc
    if not isinstance(value, list):
        raise EvalParseError("claim extraction response must be a JSON array")
    return [_claim_from_object(item, index) for index, item in enumerate(value)]


@lru_cache(maxsize=1)
def _claim_prompt() -> str:
    return _PROMPT_PATH.read_text(encoding="utf-8").strip()


class ClaimExtractor:
    """LLM-backed atomic claim extractor."""

    def __init__(self, client: LLMClient) -> None:
        self.client = client

    def build_messages(self, report_md: str) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": _claim_prompt()},
            {"role": "user", "content": f"REPORT\n{report_md}"},
        ]

    def extract(self, report_md: str) -> list[Claim]:
        return parse_claims_json(self.client.complete(self.build_messages(report_md)))


def _normalise_heading(heading: str) -> str:
    normalised = re.sub(r"\s+", " ", heading.strip().lower().replace("–", "-"))
    return re.sub(r"^\d+(?:\.\d+)*[.)]?\s+", "", normalised)


def _sentences(line: str) -> Sequence[str]:
    cleaned = _LIST_PREFIX_PATTERN.sub("", line.strip())
    if not cleaned:
        return ()
    return tuple(
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+(?=[A-Z0-9[])|\s*;\s+", cleaned)
        if part.strip()
    )


class MockClaimExtractor:
    """Deterministic sentence-level extractor for offline evaluation tests."""

    def extract(self, report_md: str) -> list[Claim]:
        claims: list[Claim] = []
        section: str | None = None
        for line in report_md.splitlines():
            heading = _HEADING_PATTERN.match(line)
            if heading:
                normalised = _normalise_heading(heading.group(1))
                section = _HEADING_TO_SECTION.get(normalised)
                if section is None:
                    underscore = normalised.replace("-", " ").replace(" ", "_")
                    section = underscore if underscore in REPORT_SECTIONS else None
                continue
            if section is None:
                continue
            for sentence in _sentences(line):
                refs = [match.group(0).upper() for match in _REF_PATTERN.finditer(sentence)]
                assertion_text = _REF_PATTERN.sub("", sentence)
                if re.search(r"\d", assertion_text) or _FEATURE_PATTERN.search(
                    assertion_text
                ):
                    claim_type = "feature"
                elif section in ("immediate_actions", "longer_term_remediation"):
                    claim_type = "procedural"
                else:
                    claim_type = "knowledge"
                claims.append(Claim(sentence, section, claim_type, refs))
        return claims
