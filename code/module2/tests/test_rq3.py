"""Focused offline tests for RQ3 export and agreement scoring."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ..evaluation import rq3_sheet
from ..evaluation.claims import Claim, MockClaimExtractor
from ..evaluation.judge import JudgeResult, MockJudgeClient
from ..evaluation.metrics import cohens_kappa, weighted_kappa
from ..evaluation.rq3_sheet import export_rq3_sheet, score_rq3
from ..generation import (
    GEN_FULL_RAG,
    MockLLMClient,
    ReportCache,
    generate_report,
    load_cases,
)
from ..generation.cases import AlertCase, EvidenceItem
from ..generation.prompt_builder import _alert_data, _context_block, format_evidence
from ..retrieval import RetrievedChunk

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


class _SyntheticRetriever:
    records_by_id = {
        "chunk-a": {
            "chunk_id": "chunk-a",
            "doc_id": "document-a",
            "text": "Exact synthetic context body.",
            "title": "Synthetic Context",
        }
    }

    def retrieve(self, section, attack_type, device_category, config):
        del section, attack_type, device_category, config
        return []


class _SyntheticClaimExtractor:
    def __init__(self, claims_by_report):
        self.claims_by_report = claims_by_report

    def extract(self, report_md):
        return self.claims_by_report[report_md]


class _SyntheticJudge:
    labels = [
        "supported",
        "unsupported_but_true",
        "unsupported_and_false",
    ]
    scores = {
        "factual_accuracy": 87651,
        "actionability_device_specific": 87652,
        "actionability_phases_separated": 87653,
        "actionability_matches_category": 87654,
    }

    def judge(
        self,
        case,
        report_md,
        claims,
        chunks_by_section,
        *,
        config_name,
        use_cache,
    ):
        del case, report_md, chunks_by_section, config_name, use_cache
        return JudgeResult(
            claim_labels=[
                {"text": claim.text, "label": self.labels[index % len(self.labels)]}
                for index, claim in enumerate(claims)
            ],
            **self.scores,
            hallucination_check=0,
            comments="synthetic judge answer",
        )


@pytest.fixture
def synthetic_rq3_export(tmp_path, monkeypatch):
    cases = [
        AlertCase(
            case_id=case_id,
            device_name=f"Device {case_id}",
            device_category="security_camera",
            y_pred="mirai_ack",
            p_top1=0.72,
            top2_class="benign",
            p_top2=0.18,
            p_pair=0.90,
            margin=0.54,
            entropy=0.31,
            evidence=[
                EvidenceItem(
                    feature=f"feature_{case_id}",
                    value=12.0,
                    benign_median=3.0,
                    benign_std=1.0,
                    benign_p99=7.0,
                    screen="discriminative",
                )
            ],
        )
        for case_id in ("synthetic-b", "synthetic-a")
    ]
    reports = {case.case_id: f"report for {case.case_id}" for case in cases}
    claims_by_report = {
        reports[case.case_id]: [
            Claim(
                f"Context-backed claim for {case.case_id} [C1].",
                "threat_assessment",
                "knowledge",
                ["[C1]"],
            ),
            Claim(
                f"Evidence-backed claim for {case.case_id} [E1].",
                "observable_indicators",
                "knowledge",
                ["[E1]"],
            ),
            Claim(
                f"Uncited claim for {case.case_id}.",
                "attack_mechanism",
                "knowledge",
                [],
            ),
        ]
        for case in cases
    }

    monkeypatch.setattr(rq3_sheet, "DEFAULT_CACHE_DIR", tmp_path / "report-cache")
    monkeypatch.setattr(
        rq3_sheet, "DEFAULT_CLAIM_CACHE_DIR", tmp_path / "claim-cache"
    )
    monkeypatch.setattr(
        rq3_sheet, "_select_case_ids", lambda split, n: [case.case_id for case in cases]
    )
    monkeypatch.setattr(rq3_sheet, "load_cases", lambda path: cases)

    def fake_generate(case, config, **kwargs):
        del config, kwargs
        chunk_ids = (
            {"threat_assessment": ["chunk-a"]}
            if case.case_id == "synthetic-a"
            else {}
        )
        return SimpleNamespace(
            report_md=reports[case.case_id], chunk_ids_by_section=chunk_ids
        )

    monkeypatch.setattr(rq3_sheet, "generate_report", fake_generate)
    retriever = _SyntheticRetriever()
    extractor = _SyntheticClaimExtractor(claims_by_report)
    judge = _SyntheticJudge()
    export_rq3_sheet(
        split="frozen",
        n=2,
        out_dir=tmp_path,
        client=MockLLMClient(),
        retriever=retriever,
        claim_extractor=extractor,
        use_cache=False,
        judge_client=judge,
    )
    return SimpleNamespace(
        cases=cases,
        reports=reports,
        claims_by_report=claims_by_report,
        retriever=retriever,
        extractor=extractor,
        judge=judge,
    )


def test_exported_claims_include_round_trippable_cited_refs(
    tmp_path, synthetic_rq3_export
):
    claims_path = tmp_path / rq3_sheet.CLAIMS_FILENAME
    with claims_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        assert reader.fieldnames == [
            "case_id",
            "claim_index",
            "section",
            "cited_refs",
            "claim_text",
            "human_label",
        ]

    expected = {
        (case.case_id, str(index)): claim.cited_refs
        for case in synthetic_rq3_export.cases
        for index, claim in enumerate(
            synthetic_rq3_export.claims_by_report[
                synthetic_rq3_export.reports[case.case_id]
            ]
        )
    }
    assert {
        (row["case_id"], row["claim_index"]): json.loads(row["cited_refs"])
        for row in rows
    } == expected


def test_case_materials_contain_exact_prompt_builder_blocks(
    tmp_path, synthetic_rq3_export
):
    materials = (tmp_path / rq3_sheet.MATERIALS_FILENAME).read_text(encoding="utf-8")
    assert "material the judge received" in materials
    assert "entailment criterion" in materials
    assert materials.count("\n## synthetic-") == len(synthetic_rq3_export.cases)

    context_chunk = RetrievedChunk(
        chunk_id="chunk-a",
        doc_id="document-a",
        score=0.0,
        text="Exact synthetic context body.",
        metadata={"title": "Synthetic Context"},
    )
    cases_by_id = {case.case_id: case for case in synthetic_rq3_export.cases}
    expected_context = {
        "synthetic-a": _context_block({"threat_assessment": [context_chunk]}),
        "synthetic-b": _context_block({}),
    }
    for case_id in sorted(cases_by_id):
        case = cases_by_id[case_id]
        section = materials.split(f"## {case_id}\n", 1)[1].split("\n## ", 1)[0]
        assert f"### ALERT DATA\n{_alert_data(case)}" in section
        assert f"### EVIDENCE\nEVIDENCE\n{format_evidence(case.evidence)}" in section
        if expected_context[case_id]:
            assert f"### CONTEXT\n{expected_context[case_id]}" in section
        else:
            assert "### CONTEXT\n(no retrieved context)" in section


def test_case_materials_do_not_contain_judge_answers(tmp_path, synthetic_rq3_export):
    materials = (tmp_path / rq3_sheet.MATERIALS_FILENAME).read_text(encoding="utf-8")
    case_materials = materials.split("\n## ", 1)[1]
    for label in synthetic_rq3_export.judge.labels:
        assert label not in case_materials
    for score in synthetic_rq3_export.judge.scores.values():
        assert str(score) not in materials
    assert "judge_label" not in materials
    assert all(field not in materials for field in SCORE_FIELDS)


def test_refresh_claims_preserves_reports_and_reference_bytes(
    tmp_path, monkeypatch, synthetic_rq3_export
):
    reports_path = tmp_path / rq3_sheet.REPORTS_FILENAME
    reference_path = tmp_path / rq3_sheet.JUDGE_REFERENCE_FILENAME
    sentinel_reports = (
        b"case_id,report_md,factual_accuracy,actionability_device_specific,"
        b"actionability_phases_separated,actionability_matches_category\r\n"
        b"human-case,hand annotated report,5,1,1,1\r\n"
    )
    sentinel_reference = b"sentinel judge reference bytes\n"
    reports_path.write_bytes(sentinel_reports)
    reference_path.write_bytes(sentinel_reference)

    monkeypatch.setattr(
        rq3_sheet, "Retriever", lambda: synthetic_rq3_export.retriever
    )
    monkeypatch.setattr(
        rq3_sheet, "MockClaimExtractor", lambda: synthetic_rq3_export.extractor
    )
    exit_code = rq3_sheet.main(
        [
            "refresh-claims",
            "--mock",
            "--split",
            "frozen",
            "--n",
            "2",
            "--out-dir",
            str(tmp_path),
        ]
    )

    assert exit_code == 0
    assert (tmp_path / rq3_sheet.CLAIMS_FILENAME).is_file()
    assert (tmp_path / rq3_sheet.MATERIALS_FILENAME).is_file()
    assert reports_path.read_bytes() == sentinel_reports
    assert reference_path.read_bytes() == sentinel_reference


@pytest.mark.parametrize(
    ("filename", "human_field", "human_value"),
    [
        (rq3_sheet.REPORTS_FILENAME, "factual_accuracy", "5"),
        (rq3_sheet.CLAIMS_FILENAME, "human_label", "supported"),
    ],
)
def test_full_export_requires_force_for_annotated_sheets(
    tmp_path,
    synthetic_rq3_export,
    filename,
    human_field,
    human_value,
):
    path = tmp_path / filename
    rows = _read_csv(path)
    rows[0][human_field] = human_value
    _write_csv(path, list(rows[0]), rows)

    export_kwargs = {
        "split": "frozen",
        "n": 2,
        "out_dir": tmp_path,
        "client": MockLLMClient(),
        "retriever": synthetic_rq3_export.retriever,
        "claim_extractor": synthetic_rq3_export.extractor,
        "use_cache": False,
        "judge_client": synthetic_rq3_export.judge,
    }
    with pytest.raises(
        FileExistsError,
        match=rf"{filename}.+--force.+discard human annotations",
    ):
        export_rq3_sheet(**export_kwargs)

    export_rq3_sheet(**export_kwargs, force=True)
    assert all(row[human_field] == "" for row in _read_csv(path))


def test_full_export_overwrites_all_blank_sheets_without_force(
    tmp_path, synthetic_rq3_export
):
    reports_path = tmp_path / rq3_sheet.REPORTS_FILENAME
    claims_path = tmp_path / rq3_sheet.CLAIMS_FILENAME
    report_rows = _read_csv(reports_path)
    claim_rows = _read_csv(claims_path)
    report_rows[0]["report_md"] = "stale blank report row"
    claim_rows[0]["claim_text"] = "stale blank claim row"
    _write_csv(reports_path, list(report_rows[0]), report_rows)
    _write_csv(claims_path, list(claim_rows[0]), claim_rows)

    export_rq3_sheet(
        split="frozen",
        n=2,
        out_dir=tmp_path,
        client=MockLLMClient(),
        retriever=synthetic_rq3_export.retriever,
        claim_extractor=synthetic_rq3_export.extractor,
        use_cache=False,
        judge_client=synthetic_rq3_export.judge,
    )

    assert "stale blank report row" not in reports_path.read_text(encoding="utf-8")
    assert "stale blank claim row" not in claims_path.read_text(encoding="utf-8")


def test_score_rq3_accepts_claims_sheet_with_cited_refs(tmp_path):
    reports, claims, reference = _scoring_artifacts(
        tmp_path,
        CLAIM_LABELS,
        CLAIM_LABELS,
        {"case-1": [3, 1, 1, 1]},
        {"case-1": [3, 1, 1, 1]},
    )
    claim_rows = _read_csv(claims)
    for index, row in enumerate(claim_rows, start=1):
        row["cited_refs"] = json.dumps([f"[E{index}]"])
    _write_csv(
        claims,
        [
            "case_id",
            "claim_index",
            "section",
            "cited_refs",
            "claim_text",
            "human_label",
        ],
        claim_rows,
    )

    output = score_rq3(reports, claims, reference, out=tmp_path / "agreement.csv")

    assert set(_read_csv(output)[0]) == {
        "metric",
        "method",
        "kappa",
        "n",
        "raw_agreement",
        "n_distinct_human",
        "n_distinct_judge",
        "degenerate",
    }


def test_score_rq3_flags_both_raters_constant_and_equal(tmp_path):
    reports, claims, reference = _scoring_artifacts(
        tmp_path,
        CLAIM_LABELS,
        CLAIM_LABELS,
        {
            "case-1": [1, 1, 0, 0],
            "case-2": [2, 1, 1, 1],
            "case-3": [3, 1, 0, 1],
        },
        {
            "case-1": [1, 1, 0, 0],
            "case-2": [2, 1, 1, 1],
            "case-3": [3, 1, 0, 1],
        },
    )

    output = score_rq3(
        reports, claims, reference, out=tmp_path / "agreement.csv"
    )
    row = _agreement_rows(output)["actionability_device_specific"]

    assert row["degenerate"] == "True"
    assert float(row["raw_agreement"]) == 1.0
    assert float(row["kappa"]) == 1.0
    assert row["n_distinct_human"] == "1"
    assert row["n_distinct_judge"] == "1"


def test_score_rq3_flags_one_constant_rater_and_preserves_raw_agreement(tmp_path):
    reports, claims, reference = _scoring_artifacts(
        tmp_path,
        CLAIM_LABELS,
        CLAIM_LABELS,
        {
            "case-1": [1, 1, 0, 0],
            "case-2": [2, 0, 1, 1],
            "case-3": [3, 1, 0, 1],
            "case-4": [4, 0, 1, 0],
        },
        {
            "case-1": [1, 1, 0, 0],
            "case-2": [2, 1, 1, 1],
            "case-3": [3, 1, 0, 1],
            "case-4": [4, 1, 1, 0],
        },
    )

    output = score_rq3(
        reports, claims, reference, out=tmp_path / "agreement.csv"
    )
    row = _agreement_rows(output)["actionability_device_specific"]

    assert row["degenerate"] == "True"
    assert float(row["raw_agreement"]) == 0.5
    assert float(row["raw_agreement"]) != 0.0
    assert float(row["kappa"]) == 0.0
    assert row["n_distinct_human"] == "2"
    assert row["n_distinct_judge"] == "1"


def test_score_rq3_records_distinct_counts_and_hand_computed_raw_agreement(tmp_path):
    reports, claims, reference = _scoring_artifacts(
        tmp_path,
        CLAIM_LABELS,
        CLAIM_LABELS,
        {
            "case-1": [1, 0, 0, 0],
            "case-2": [2, 0, 1, 1],
            "case-3": [3, 1, 0, 1],
            "case-4": [4, 1, 1, 0],
        },
        {
            "case-1": [1, 0, 0, 0],
            "case-2": [2, 1, 1, 1],
            "case-3": [4, 1, 1, 0],
            "case-4": [5, 0, 1, 0],
        },
    )

    output = score_rq3(
        reports, claims, reference, out=tmp_path / "agreement.csv"
    )
    row = _agreement_rows(output)["factual_accuracy"]

    assert row["degenerate"] == "False"
    assert row["n_distinct_human"] == "4"
    assert row["n_distinct_judge"] == "4"
    assert round(float(row["raw_agreement"]), 4) == 0.5000


def test_score_rq3_stdout_warns_only_for_degenerate_metrics(tmp_path, capsys):
    degenerate_dir = tmp_path / "degenerate"
    degenerate_dir.mkdir()
    reports, claims, reference = _scoring_artifacts(
        degenerate_dir,
        CLAIM_LABELS,
        CLAIM_LABELS,
        {
            "case-1": [1, 1, 0, 0],
            "case-2": [2, 0, 1, 1],
            "case-3": [3, 1, 0, 1],
        },
        {
            "case-1": [1, 1, 0, 0],
            "case-2": [2, 1, 1, 1],
            "case-3": [3, 1, 0, 1],
        },
    )
    score_rq3(
        reports,
        claims,
        reference,
        out=degenerate_dir / "agreement.csv",
    )
    warning_output = capsys.readouterr().out

    assert "actionability_device_specific" in warning_output
    assert "NOT INTERPRETABLE" in warning_output
    assert "judge assigned a single value to all 3 cases" in warning_output

    healthy_dir = tmp_path / "healthy"
    healthy_dir.mkdir()
    reports, claims, reference = _scoring_artifacts(
        healthy_dir,
        CLAIM_LABELS,
        CLAIM_LABELS,
        {
            "case-1": [1, 0, 0, 0],
            "case-2": [2, 1, 1, 1],
            "case-3": [3, 0, 0, 1],
        },
        {
            "case-1": [1, 0, 0, 0],
            "case-2": [2, 1, 1, 1],
            "case-3": [3, 0, 1, 0],
        },
    )
    score_rq3(reports, claims, reference, out=healthy_dir / "agreement.csv")
    healthy_output = capsys.readouterr().out

    assert "RQ3 human-vs-judge agreement" in healthy_output
    assert "NOT INTERPRETABLE" not in healthy_output
