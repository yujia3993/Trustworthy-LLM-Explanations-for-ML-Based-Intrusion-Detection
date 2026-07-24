"""Focused offline tests for RQ3 export and agreement scoring."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from ..evaluation import rq3_sheet
from ..evaluation.claims import MockClaimExtractor
from ..evaluation.judge import MockJudgeClient
from ..evaluation.metrics import cohens_kappa, weighted_kappa
from ..evaluation.rq3_sheet import export_rq3_sheet, score_rq3
from ..generation import (
    GEN_FULL_RAG,
    MockLLMClient,
    ReportCache,
    generate_report,
    load_cases,
)

SCORE_FIELDS = [
    "factual_accuracy",
    "actionability_device_specific",
    "actionability_phases_separated",
    "actionability_matches_category",
]
CLAIM_LABELS = [
    "supported",
    "unsupported_but_true",
    "unsupported_and_false",
]


class _EmptyRetriever:
    records_by_id: dict[str, dict[str, object]] = {}

    def retrieve(self, section, attack_type, device_category, config):
        del section, attack_type, device_category, config
        return []


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _scoring_artifacts(
    tmp_path: Path,
    human_claims: list[str],
    judge_claims: list[str],
    human_reports: dict[str, list[int]],
    judge_reports: dict[str, list[int]],
    *,
    human_claim_indices: list[int] | None = None,
    judge_claim_indices: list[int] | None = None,
) -> tuple[Path, Path, Path]:
    reports_path = tmp_path / "reports.csv"
    claims_path = tmp_path / "claims.csv"
    reference_path = tmp_path / "reference.csv"
    human_indices = human_claim_indices or list(range(len(human_claims)))
    judge_indices = judge_claim_indices or list(range(len(judge_claims)))

    report_rows = []
    for case_id, values in human_reports.items():
        report_rows.append(
            {
                "case_id": case_id,
                "report_md": f"report for {case_id}",
                **dict(zip(SCORE_FIELDS, values)),
            }
        )
    _write_csv(
        reports_path,
        ["case_id", "report_md", *SCORE_FIELDS],
        report_rows,
    )

    _write_csv(
        claims_path,
        ["case_id", "claim_index", "section", "claim_text", "human_label"],
        [
            {
                "case_id": "case-1",
                "claim_index": index,
                "section": "threat_assessment",
                "claim_text": f"claim {index}",
                "human_label": label,
            }
            for index, label in zip(human_indices, human_claims)
        ],
    )

    reference_rows: list[dict[str, object]] = [
        {
            "kind": "claim",
            "case_id": "case-1",
            "claim_index": index,
            "judge_label": label,
            **{field: "" for field in SCORE_FIELDS},
        }
        for index, label in zip(judge_indices, judge_claims)
    ]
    for case_id, values in judge_reports.items():
        reference_rows.append(
            {
                "kind": "report",
                "case_id": case_id,
                "claim_index": "",
                "judge_label": "",
                **dict(zip(SCORE_FIELDS, values)),
            }
        )
    _write_csv(
        reference_path,
        ["kind", "case_id", "claim_index", "judge_label", *SCORE_FIELDS],
        reference_rows,
    )
    return reports_path, claims_path, reference_path


def _agreement_rows(path: Path) -> dict[str, dict[str, str]]:
    return {row["metric"]: row for row in _read_csv(path)}


def test_score_rq3_perfect_agreement(tmp_path, capsys):
    reports, claims, reference = _scoring_artifacts(
        tmp_path,
        CLAIM_LABELS,
        CLAIM_LABELS,
        {
            "case-1": [2, 0, 1, 0],
            "case-2": [5, 1, 0, 1],
        },
        {
            "case-1": [2, 0, 1, 0],
            "case-2": [5, 1, 0, 1],
        },
    )

    output = score_rq3(
        reports, claims, reference, out=tmp_path / "agreement.csv"
    )

    rows = _agreement_rows(output)
    assert set(rows) == {"claim_labels", *SCORE_FIELDS}
    assert all(float(row["kappa"]) == 1.0 for row in rows.values())
    assert rows["claim_labels"]["n"] == "3"
    assert all(rows[field]["n"] == "2" for field in SCORE_FIELDS)
    assert "RQ3 human-vs-judge agreement" in capsys.readouterr().out


def test_score_rq3_partial_agreement_matches_existing_metrics(tmp_path):
    human_claims = [
        "supported",
        "supported",
        "unsupported_but_true",
        "unsupported_but_true",
        "unsupported_and_false",
        "unsupported_and_false",
    ]
    judge_claims = [
        "supported",
        "unsupported_but_true",
        "unsupported_but_true",
        "unsupported_and_false",
        "unsupported_and_false",
        "supported",
    ]
    human_reports = {
        "case-1": [1, 0, 0, 1],
        "case-2": [2, 0, 1, 1],
        "case-3": [4, 1, 0, 0],
        "case-4": [5, 1, 1, 0],
    }
    judge_reports = {
        "case-1": [1, 0, 0, 1],
        "case-2": [3, 1, 1, 0],
        "case-3": [3, 1, 1, 0],
        "case-4": [5, 0, 1, 0],
    }
    reports, claims, reference = _scoring_artifacts(
        tmp_path,
        human_claims,
        judge_claims,
        human_reports,
        judge_reports,
    )

    output = score_rq3(
        reports, claims, reference, out=tmp_path / "agreement.csv"
    )
    actual = _agreement_rows(output)

    assert round(float(actual["claim_labels"]["kappa"]), 4) == round(
        cohens_kappa(human_claims, judge_claims), 4
    )
    for offset, field in enumerate(SCORE_FIELDS[1:], start=1):
        human = [values[offset] for values in human_reports.values()]
        judge = [values[offset] for values in judge_reports.values()]
        assert round(float(actual[field]["kappa"]), 4) == round(
            cohens_kappa(human, judge), 4
        )
    assert round(float(actual["factual_accuracy"]["kappa"]), 4) == round(
        weighted_kappa(
            [values[0] for values in human_reports.values()],
            [values[0] for values in judge_reports.values()],
            "linear",
        ),
        4,
    )


@pytest.mark.parametrize(
    ("human_indices", "judge_indices", "expected"),
    [
        ([0, 1], [0], r"\('case-1', 1\).+human sheet.+missing"),
        ([0], [0, 1], r"\('case-1', 1\).+judge reference.+missing"),
    ],
)
def test_score_rq3_rejects_claim_alignment_failures(
    tmp_path, human_indices, judge_indices, expected
):
    reports, claims, reference = _scoring_artifacts(
        tmp_path,
        ["supported"] * len(human_indices),
        ["supported"] * len(judge_indices),
        {"case-1": [3, 1, 1, 1]},
        {"case-1": [3, 1, 1, 1]},
        human_claim_indices=human_indices,
        judge_claim_indices=judge_indices,
    )

    with pytest.raises(ValueError, match=expected):
        score_rq3(reports, claims, reference, out=tmp_path / "agreement.csv")


def test_score_rq3_rejects_unfilled_human_label(tmp_path):
    reports, claims, reference = _scoring_artifacts(
        tmp_path,
        [""],
        ["supported"],
        {"case-1": [3, 1, 1, 1]},
        {"case-1": [3, 1, 1, 1]},
    )

    with pytest.raises(
        ValueError, match=r"\('case-1', 0\).+human_label.+unfilled"
    ):
        score_rq3(reports, claims, reference, out=tmp_path / "agreement.csv")


@pytest.mark.parametrize(
    ("human_claim", "human_scores", "expected"),
    [
        ("not_a_label", [3, 1, 1, 1], r"\('case-1', 0\).+out-of-domain"),
        ("supported", [6, 1, 1, 1], r"case-1.+factual_accuracy.+out-of-domain"),
        ("supported", [3, 2, 1, 1], r"case-1.+device_specific.+out-of-domain"),
    ],
)
def test_score_rq3_rejects_out_of_domain_human_values(
    tmp_path, human_claim, human_scores, expected
):
    reports, claims, reference = _scoring_artifacts(
        tmp_path,
        [human_claim],
        ["supported"],
        {"case-1": human_scores},
        {"case-1": [3, 1, 1, 1]},
    )

    with pytest.raises(ValueError, match=expected):
        score_rq3(reports, claims, reference, out=tmp_path / "agreement.csv")


def test_mock_export_writes_frozen_aligned_sheets_and_preserves_stratification(
    tmp_path, monkeypatch
):
    report_cache_dir = tmp_path / "report_cache"
    claim_cache_dir = tmp_path / "claim_cache"
    monkeypatch.setattr(rq3_sheet, "DEFAULT_CACHE_DIR", report_cache_dir)
    monkeypatch.setattr(rq3_sheet, "DEFAULT_CLAIM_CACHE_DIR", claim_cache_dir)

    paths = export_rq3_sheet(
        split="frozen",
        n=20,
        out_dir=tmp_path,
        client=MockLLMClient(),
        retriever=_EmptyRetriever(),
        claim_extractor=MockClaimExtractor(),
        use_cache=True,
        judge_client=MockJudgeClient(),
    )

    assert len(paths) == 3
    assert all(path.is_file() and path.parent == tmp_path for path in paths)
    report_rows = _read_csv(tmp_path / rq3_sheet.REPORTS_FILENAME)
    claim_rows = _read_csv(tmp_path / rq3_sheet.CLAIMS_FILENAME)
    reference_rows = _read_csv(tmp_path / rq3_sheet.JUDGE_REFERENCE_FILENAME)

    assert len(report_rows) == 20
    assert all(row[field] == "" for row in report_rows for field in SCORE_FIELDS)
    assert claim_rows
    assert all(row["human_label"] == "" for row in claim_rows)
    assert all(row["claim_text"] for row in claim_rows)
    assert len(
        {(row["case_id"], row["claim_index"]) for row in claim_rows}
    ) == len(claim_rows)

    reference_claims = [row for row in reference_rows if row["kind"] == "claim"]
    reference_reports = [row for row in reference_rows if row["kind"] == "report"]
    assert len(reference_claims) == len(claim_rows)
    assert all(row["judge_label"] in CLAIM_LABELS for row in reference_claims)
    assert len(reference_reports) == 20
    assert all(row[field] != "" for row in reference_reports for field in SCORE_FIELDS)

    selected_ids = {row["case_id"] for row in report_rows}
    raw_cases = json.loads(
        (rq3_sheet.CASES_DIR / "eval_cases_frozen.json").read_text(encoding="utf-8")
    )
    strata = {
        item["case_id"]: item.get("metadata", {}).get("stratum", "unknown")
        for item in raw_cases
    }
    assert sum(strata[case_id] == "hedged_pair" for case_id in selected_ids) >= 8
    assert sum(strata[case_id] == "assertive_error" for case_id in selected_ids) >= 2

    first_row = report_rows[0]
    case = next(
        case
        for case in load_cases(rq3_sheet.CASES_DIR / "eval_cases_frozen.json")
        if case.case_id == first_row["case_id"]
    )
    generated = generate_report(
        case,
        GEN_FULL_RAG,
        retriever=_EmptyRetriever(),
        client=MockLLMClient(),
        cache=ReportCache(report_cache_dir),
        use_cache=True,
    )
    assert generated.from_cache is True
    assert first_row["report_md"] == generated.report_md
