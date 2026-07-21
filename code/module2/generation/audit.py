"""Machine-checkable confidence-register audit gates."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from .cases import AlertCase
from .pipeline import REPORT_SECTIONS
from .registers import Register, select_register

_RULES_PATH = Path(__file__).resolve().parent / "audit_rules.json"


@lru_cache(maxsize=1)
def _load_audit_rules() -> dict[str, Any]:
    return json.loads(_RULES_PATH.read_text(encoding="utf-8"))


@dataclass(frozen=True, slots=True)
class AuditResult:
    passed: bool
    gate_results: dict[str, bool]
    violations: list[str]


def audit_report(report_md: str, case: AlertCase, register: Register) -> AuditResult:
    rules = _load_audit_rules()
    gates = rules["gates"]
    results = {name: True for name in gates}
    violations: list[str] = []

    # Keep the audit and generation layers on one shared section vocabulary.
    _ = REPORT_SECTIONS

    gate1 = "gate1_register_mapping"
    expected = select_register(case)
    if register != expected:
        results[gate1] = False
        violations.append(
            f"{gate1}: expected register {expected!r}, got {register!r}"
        )

    gate2 = "gate2_hedged_disclosures"
    gate2_rules = gates[gate2]
    if register in gate2_rules.get("applies_to", []):
        for pattern in gate2_rules["required_patterns"]:
            if re.search(pattern, report_md) is None:
                results[gate2] = False
                violations.append(f"{gate2}: required pattern not found: {pattern}")

    gate3 = "gate3_no_ordering_language"
    gate3_rules = gates[gate3]
    if register in gate3_rules.get("applies_to", []):
        for pattern in gate3_rules["forbidden_patterns"]:
            match = re.search(pattern, report_md)
            if match is not None:
                results[gate3] = False
                violations.append(
                    f"{gate3}: forbidden pattern {pattern} matched {match.group(0)!r}"
                )

    gate4 = "gate4_probability_consistency"
    probability_format = rules["probability_format"]
    p_top1 = probability_format.format(case.p_top1)
    p_top2 = probability_format.format(case.p_top2)
    p_pair = probability_format.format(case.p_pair)
    if register == "assertive":
        if p_top1 not in report_md:
            results[gate4] = False
            violations.append(f"{gate4}: required p_top1 {p_top1!r} not found")
    elif register == "hedged_pair":
        if p_pair not in report_md:
            results[gate4] = False
            violations.append(f"{gate4}: required p_pair {p_pair!r} not found")
        for name, value in (("p_top1", p_top1), ("p_top2", p_top2)):
            if value != p_pair and value in report_md:
                results[gate4] = False
                violations.append(
                    f"{gate4}: forbidden within-pair {name} {value!r} found"
                )
    elif register == "hedged_generic":
        for name, value in (("p_top1", p_top1), ("p_top2", p_top2)):
            if value not in report_md:
                results[gate4] = False
                violations.append(f"{gate4}: required {name} {value!r} not found")

    return AuditResult(
        passed=all(results.values()),
        gate_results=results,
        violations=violations,
    )
