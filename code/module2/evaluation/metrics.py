"""Pure agreement metrics and configuration-level evaluation aggregation."""

from __future__ import annotations

from collections import Counter
from statistics import fmean
from typing import Any, Iterable, Sequence

from ..generation.audit import AuditResult
from .feature_verify import FeatureVerification
from .judge import JudgeResult, load_judge_rubric


def aggregate_claims(labels: Iterable[str]) -> dict[str, int | float]:
    """Count taxonomy labels and compute the two protocol headline rates."""

    allowed = tuple(load_judge_rubric()["claim_labels"])
    counts = Counter(labels)
    unknown = set(counts) - set(allowed)
    if unknown:
        raise ValueError(f"unknown claim labels: {sorted(unknown)}")
    total = sum(counts.values())
    result: dict[str, int | float] = {label: counts[label] for label in allowed}
    result["total_claims"] = total
    result["hallucination_rate"] = (
        counts["unsupported_and_false"] / total if total else 0.0
    )
    result["faithfulness"] = counts["supported"] / total if total else 0.0
    return result


def _validate_pairs(a: Sequence[Any], b: Sequence[Any]) -> None:
    if len(a) != len(b):
        raise ValueError("rating lists must have equal length")
    if not a:
        raise ValueError("rating lists must not be empty")


def cohens_kappa(a: list[Any], b: list[Any]) -> float:
    """Return unweighted Cohen's kappa for two equal-length rating lists."""

    _validate_pairs(a, b)
    categories = set(a) | set(b)
    count_a = Counter(a)
    count_b = Counter(b)
    n = len(a)
    observed = sum(left == right for left, right in zip(a, b)) / n
    expected = sum(count_a[item] * count_b[item] for item in categories) / (n * n)
    denominator = 1.0 - expected
    if denominator == 0:
        return 1.0 if observed == 1.0 else 0.0
    return (observed - expected) / denominator


def weighted_kappa(
    a: list[int], b: list[int], weights: str = "linear"
) -> float:
    """Return linearly or quadratically weighted kappa for ordinal 1-5 ratings."""

    _validate_pairs(a, b)
    if weights not in ("linear", "quadratic"):
        raise ValueError("weights must be 'linear' or 'quadratic'")
    if any(value not in range(1, 6) for value in (*a, *b)):
        raise ValueError("weighted kappa ratings must be integers from 1 to 5")
    count_a = Counter(a)
    count_b = Counter(b)
    n = len(a)

    def disagreement(left: int, right: int) -> float:
        distance = abs(left - right) / 4.0
        return distance if weights == "linear" else distance * distance

    observed = sum(disagreement(left, right) for left, right in zip(a, b)) / n
    expected = sum(
        disagreement(left, right) * count_a[left] * count_b[right]
        for left in range(1, 6)
        for right in range(1, 6)
    ) / (n * n)
    if expected == 0:
        return 1.0 if observed == 0 else 0.0
    return 1.0 - observed / expected


def summarize_config(
    config_name: str,
    claim_labels: Iterable[str],
    verifications: Sequence[FeatureVerification],
    judge_results: Sequence[JudgeResult],
    audits: Sequence[AuditResult],
    fallback_flags: Sequence[bool] | None = None,
    needs_review_flags: Sequence[bool] | None = None,
) -> dict[str, Any]:
    """Build one stable summary row for a generation configuration."""

    aggregate = aggregate_claims(claim_labels)
    numeric_count = sum(len(item.numeric_tokens) for item in verifications)
    fabricated_count = sum(len(item.fabricated_numbers) for item in verifications)
    invalid_ref_count = sum(len(item.invalid_refs) for item in verifications)
    contextual_misuse_count = sum(
        len(item.contextual_misuse) for item in verifications
    )
    row: dict[str, Any] = {
        "config": config_name,
        "n_cases": len(audits),
        **aggregate,
        "fabricated_number_count": fabricated_count,
        "numeric_token_count": numeric_count,
        "fabricated_number_rate": fabricated_count / numeric_count
        if numeric_count
        else 0.0,
        "invalid_ref_count": invalid_ref_count,
        "contextual_misuse_count": contextual_misuse_count,
        "contextual_misuse_rate": contextual_misuse_count / len(verifications)
        if verifications
        else 0.0,
        "factual_accuracy_mean": fmean(
            result.factual_accuracy for result in judge_results
        )
        if judge_results
        else 0.0,
        "actionability_device_specific_mean": fmean(
            result.actionability_device_specific for result in judge_results
        )
        if judge_results
        else 0.0,
        "actionability_phases_separated_mean": fmean(
            result.actionability_phases_separated for result in judge_results
        )
        if judge_results
        else 0.0,
        "actionability_matches_category_mean": fmean(
            result.actionability_matches_category for result in judge_results
        )
        if judge_results
        else 0.0,
        "hallucination_check_mean": fmean(
            result.hallucination_check for result in judge_results
        )
        if judge_results
        else 0.0,
        "n_fallback": sum(bool(value) for value in (fallback_flags or ())),
        "n_needs_review": sum(bool(value) for value in (needs_review_flags or ())),
    }
    gate_names = sorted(
        {name for audit in audits for name in audit.gate_results}
    )
    for gate_name in gate_names:
        row[f"{gate_name}_pass_rate"] = (
            sum(audit.gate_results.get(gate_name, False) for audit in audits)
            / len(audits)
            if audits
            else 0.0
        )
    row["all_gates_pass_rate"] = (
        sum(audit.passed for audit in audits) / len(audits) if audits else 0.0
    )
    return row

