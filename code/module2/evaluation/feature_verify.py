"""Deterministic verification of numeric and contextual feature claims."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from ..generation.cases import AlertCase
from .claims import Claim

_NUMBER_PATTERN = re.compile(
    r"(?<![\w.])[-+]?(?:(?:\d{1,3}(?:,\d{3})+)|\d+)(?:\.\d+)?"
    r"(?:[eE][-+]?\d+)?(?!\w|\.\d)"
)
_REF_PATTERN = re.compile(r"\[([EC])(\d+)\]", re.IGNORECASE)
_LIST_NUMBER_PATTERN = re.compile(r"^(\s*)\d+[.)](?=\s)")
_SECTION_NUMBER_PATTERN = re.compile(
    r"^\s*(?:#{1,6}\s*(?:section\s+)?\d+(?:\.\d+)*(?:[.):\s-]|$)|"
    r"section\s+\d+(?:\.\d+)*(?:[.):\s-]|$))",
    re.IGNORECASE,
)
_PROTOCOL_CONSTANTS = {"6", "17", "23", "2323", "443", "53", "123"}
_PROTOCOL_CONTEXT = re.compile(
    r"\b(?:protocol|ports?|tcp|udp|telnet|tcpdump|pcap)\b", re.IGNORECASE
)
_TIE_PHRASE = re.compile(
    r"\b(?:indicates?|confirms?|characteristic\s+of|signature\s+of|"
    r"diagnostic\s+of|identifies?)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class FeatureVerification:
    matched_numbers: list[str]
    fabricated_numbers: list[str]
    invalid_refs: list[str]
    contextual_misuse: list[str]

    @property
    def numeric_tokens(self) -> list[str]:
        """All checked tokens; useful as the fabricated-rate denominator."""

        return [*self.matched_numbers, *self.fabricated_numbers]


def _add_number_variants(allowed: set[str], formatted: str) -> None:
    allowed.add(formatted)
    allowed.add(formatted.replace(",", ""))


def build_allowed_number_strings(case: AlertCase) -> set[str]:
    """Return all case-derived numbers in the frozen prompt formats."""

    allowed: set[str] = set()
    for item in case.evidence:
        for value in (
            item.value,
            item.benign_median,
            item.benign_std,
            item.benign_p99,
        ):
            _add_number_variants(allowed, f"{value:.4g}")
        if item.benign_median != 0:
            _add_number_variants(allowed, f"{item.value / item.benign_median:.1f}")
    for probability in (
        case.p_top1,
        case.p_top2,
        case.p_pair,
        case.margin,
    ):
        _add_number_variants(allowed, f"{probability:.4f}")
    _add_number_variants(allowed, f"{case.entropy:.4f}")
    _add_number_variants(allowed, f"{case.entropy:.4g}")
    return allowed


def _is_protocol_constant(line: str, match: re.Match[str]) -> bool:
    token = match.group(0).replace(",", "")
    if token not in _PROTOCOL_CONSTANTS:
        return False
    start = max(0, match.start() - 64)
    end = min(len(line), match.end() + 64)
    return _PROTOCOL_CONTEXT.search(line[start:end]) is not None


def extract_numeric_tokens(report_md: str) -> list[str]:
    """Extract report numbers after applying the protocol's exclusions."""

    tokens: list[str] = []
    for raw_line in report_md.splitlines():
        line = _REF_PATTERN.sub("", raw_line)
        line = _LIST_NUMBER_PATTERN.sub(r"\1", line)
        if _SECTION_NUMBER_PATTERN.match(line):
            # A numbered heading's leading section number is formatting, but a
            # number later in the heading remains a substantive token.
            leading = _SECTION_NUMBER_PATTERN.match(line)
            assert leading is not None
            line = line[leading.end() :]
        for match in _NUMBER_PATTERN.finditer(line):
            if _is_protocol_constant(line, match):
                continue
            tokens.append(match.group(0))
    return tokens


def _provided_chunk_count(
    provided: Mapping[str, int | Sequence[str]] | Iterable[str] | int | None,
) -> int:
    if provided is None:
        return 0
    if isinstance(provided, int):
        return provided
    if isinstance(provided, Mapping):
        total = 0
        for value in provided.values():
            total += value if isinstance(value, int) else len(value)
        return total
    return len(list(provided))


def _sentence_candidates(report_md: str) -> Iterable[str]:
    for line in report_md.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        stripped = _LIST_NUMBER_PATTERN.sub("", stripped)
        for sentence in re.split(r"(?<=[.!?])\s+", stripped):
            sentence = sentence.strip()
            if sentence:
                yield sentence


def verify_features(
    report_md: str,
    case: AlertCase,
    provided_chunk_count_by_section: (
        Mapping[str, int | Sequence[str]] | Iterable[str] | int | None
    ) = None,
    *,
    chunk_ids: Mapping[str, Sequence[str]] | Iterable[str] | None = None,
) -> FeatureVerification:
    """Verify report-wide numbers, references, and contextual feature use."""

    if chunk_ids is not None:
        if provided_chunk_count_by_section is not None:
            raise TypeError("provide either provided_chunk_count_by_section or chunk_ids")
        provided_chunk_count_by_section = chunk_ids
    allowed = build_allowed_number_strings(case)
    numeric_tokens = extract_numeric_tokens(report_md)
    matched = [token for token in numeric_tokens if token.replace(",", "") in allowed]
    fabricated = [
        token for token in numeric_tokens if token.replace(",", "") not in allowed
    ]

    chunk_count = _provided_chunk_count(provided_chunk_count_by_section)
    invalid_refs: list[str] = []
    for match in _REF_PATTERN.finditer(report_md):
        kind, number_text = match.groups()
        number = int(number_text)
        upper = kind.upper()
        maximum = len(case.evidence) if upper == "E" else chunk_count
        if number < 1 or number > maximum:
            invalid_refs.append(f"[{upper}{number}]")

    contextual_names = [
        item.feature for item in case.evidence if item.screen == "contextual"
    ]
    contextual_misuse: list[str] = []
    for sentence in _sentence_candidates(report_md):
        if not _TIE_PHRASE.search(sentence):
            continue
        if any(
            re.search(rf"(?<!\w){re.escape(feature)}(?!\w)", sentence)
            for feature in contextual_names
        ):
            contextual_misuse.append(sentence)

    return FeatureVerification(
        matched_numbers=matched,
        fabricated_numbers=fabricated,
        invalid_refs=invalid_refs,
        contextual_misuse=contextual_misuse,
    )


def _normalise_ref(ref: str) -> str:
    match = re.fullmatch(r"\[?([EC]\d+)\]?", ref.strip(), re.IGNORECASE)
    return f"[{match.group(1).upper()}]" if match else ref.strip().upper()


def classify_feature_claim(claim: Claim, verification: FeatureVerification) -> str:
    """Apply the frozen three-path machine verdict to one feature claim."""

    claim_numbers = {
        token.replace(",", "") for token in extract_numeric_tokens(claim.text)
    }
    fabricated = {
        token.replace(",", "") for token in verification.fabricated_numbers
    }
    if claim_numbers & fabricated:
        return "unsupported_and_false"

    invalid = {_normalise_ref(ref) for ref in verification.invalid_refs}
    cited = [_normalise_ref(ref) for ref in claim.cited_refs]
    if cited and all(ref not in invalid for ref in cited):
        return "supported"
    return "unsupported_but_true"
