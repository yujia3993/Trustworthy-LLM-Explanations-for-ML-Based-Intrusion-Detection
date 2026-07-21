"""Offline tests for the Module 2 generation pipeline."""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

import pytest

from ..generation import (
    GEN_FULL_RAG,
    GEN_NAIVE_RAG,
    GEN_NO_RAG,
    GEN_SELF_CHECK,
    PROMPT_VERSION,
    REPORT_SECTIONS,
    AlertCase,
    EvidenceItem,
    LLMUnavailableError,
    MockLLMClient,
    ReportCache,
    audit_report,
    build_messages,
    format_evidence,
    generate_report,
    load_cases,
    needs_review,
    save_cases,
    select_register,
)
from ..retrieval import RetrievedChunk, Retriever, build_index
from ..retrieval.ingest import CHUNKS_SIDECAR_NAME, DEFAULT_INDEX_DIR

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "generation_cases.json"


@pytest.fixture(scope="session")
def generation_cases() -> list[AlertCase]:
    return load_cases(FIXTURE_PATH)


@pytest.fixture(scope="session")
def generation_retriever() -> Retriever:
    if not (DEFAULT_INDEX_DIR / CHUNKS_SIDECAR_NAME).exists():
        build_index(DEFAULT_INDEX_DIR)
    return Retriever(DEFAULT_INDEX_DIR)


def test_register_selection_and_review_guard(generation_cases):
    assert [select_register(case) for case in generation_cases] == [
        "assertive",
        "hedged_pair",
        "hedged_generic",
    ]
    assert not any(needs_review(case) for case in generation_cases)
    synthetic = replace(generation_cases[1], case_id="pair-review", margin=0.95)
    assert select_register(synthetic) == "assertive"
    assert needs_review(synthetic)


def test_cases_json_round_trip(generation_cases, tmp_path):
    path = tmp_path / "cases.json"
    save_cases(generation_cases, path)
    assert load_cases(path) == generation_cases


def test_case_validation_rejects_unknown_values(generation_cases):
    with pytest.raises(ValueError, match="device category"):
        replace(generation_cases[0], device_category="router")
    with pytest.raises(ValueError, match="predicted class"):
        replace(generation_cases[0], y_pred="unknown")
    with pytest.raises(ValueError, match="evidence screen"):
        replace(generation_cases[0].evidence[0], screen="other")


def test_evidence_rendering_templates_and_ratios():
    evidence = [
        EvidenceItem("above", 30.0, 10.0, 1.0, 20.0, "discriminative"),
        EvidenceItem("near", 10.5, 10.0, 1.0, 20.0, "discriminative"),
        EvidenceItem("context", 4.0, 10.0, 1.0, 20.0, "contextual"),
    ]
    rendered = format_evidence(evidence)
    assert "(DISCRIMINATIVE) above = 30 - 3.0x above" in rendered
    assert "(DISCRIMINATIVE) near = 10.5 - approximately at" in rendered
    assert "do not tie to a specific attack type" in rendered
    assert "30.0000" not in rendered


def test_evidence_rendering_zero_median():
    rendered = format_evidence(
        [
            EvidenceItem("positive", 1.0, 0.0, 0.0, 0.5, "discriminative"),
            EvidenceItem("zero", 0.0, 0.0, 0.0, 0.5, "contextual"),
        ]
    )
    assert "far above" in rendered
    assert "approximately at" in rendered


def test_build_messages_fills_register_and_context(generation_cases):
    chunk = RetrievedChunk(
        chunk_id="doc#0",
        doc_id="doc",
        score=1.0,
        text="Grounded context.",
        metadata={"title": "Test Document"},
    )
    for case in generation_cases:
        content = build_messages(
            case,
            select_register(case),
            {"threat_assessment": [chunk]},
        )[1]["content"]
        assert "ALERT DATA" in content
        assert "EVIDENCE" in content
        assert "REGISTER RULES" in content
        assert "CONTEXT" in content and "[C1] Test Document" in content
        assert not re.search(r"\{(?:p_pair|p_top1|p_top2|margin)\}", content)
    assert "0.9998" in build_messages(
        generation_cases[1], "hedged_pair", None
    )[1]["content"]


def test_cache_put_get_round_trip(tmp_path):
    cache = ReportCache(tmp_path)
    expected_key = ReportCache.key("cfg", "case", PROMPT_VERSION)
    entry = cache.put("report", "assertive", "cfg", "case", PROMPT_VERSION, "mock")
    assert cache.get("cfg", "case", PROMPT_VERSION) == entry
    assert (tmp_path / f"{expected_key}.json").exists()


def test_generate_report_uses_cache(generation_cases, tmp_path):
    cache = ReportCache(tmp_path)
    first = generate_report(
        generation_cases[0], GEN_NO_RAG, client=MockLLMClient(), cache=cache
    )
    second = generate_report(
        generation_cases[0], GEN_NO_RAG, client=MockLLMClient(), cache=cache
    )
    assert not first.from_cache
    assert second.from_cache
    assert second.report_md == first.report_md


def test_mock_hedged_pair_passes_audit(generation_cases):
    case = generation_cases[1]
    report = generate_report(
        case, GEN_NO_RAG, client=MockLLMClient(), use_cache=False
    ).report_md
    result = audit_report(report, case, "hedged_pair")
    assert result.passed
    assert all(result.gate_results.values())


def test_audit_tampered_hedged_pair_variants(generation_cases):
    case = generation_cases[1]
    report = generate_report(
        case, GEN_NO_RAG, client=MockLLMClient(), use_cache=False
    ).report_md

    ordering = audit_report(report + "\n\nit is most likely tcp", case, "hedged_pair")
    assert not ordering.gate_results["gate3_no_ordering_language"]

    no_capture = re.sub(
        r"(?m)^2\. After containment, capture.*gafgyt_udp\.\n?", "", report
    )
    disclosure = audit_report(no_capture, case, "hedged_pair")
    assert not disclosure.gate_results["gate2_hedged_disclosures"]

    wrong_probability = report.replace("0.9998", "0.5104")
    probability = audit_report(wrong_probability, case, "hedged_pair")
    assert not probability.gate_results["gate4_probability_consistency"]

    mismatch = audit_report(report, case, "assertive")
    assert not mismatch.gate_results["gate1_register_mapping"]


@pytest.mark.parametrize(
    "config", [GEN_NO_RAG, GEN_NAIVE_RAG, GEN_FULL_RAG, GEN_SELF_CHECK]
)
def test_generation_presets_end_to_end(
    config, generation_cases, generation_retriever
):
    retriever = None if config.retrieval == "none" else generation_retriever
    generated = generate_report(
        generation_cases[1],
        config,
        retriever=retriever,
        client=MockLLMClient(),
        use_cache=False,
    )
    expected_headings = (
        "Threat Assessment",
        "Attack Mechanism",
        "Observable Indicators",
        "Immediate Actions",
        "Longer-term Remediation",
        "Confidence Notes",
    )
    assert len(expected_headings) == len(REPORT_SECTIONS)
    for heading in expected_headings:
        assert f"## {heading}" in generated.report_md
    if config.retrieval == "none":
        assert generated.chunk_ids_by_section == {}
    else:
        flat_ids = [
            chunk_id
            for ids in generated.chunk_ids_by_section.values()
            for chunk_id in ids
        ]
        assert len(flat_ids) <= 12
        assert len(flat_ids) == len(set(flat_ids))


def test_fallback_is_bannered_and_not_cached(generation_cases, tmp_path):
    class UnavailableClient:
        model = "offline"

        def complete(self, messages):
            raise LLMUnavailableError("offline")

    cache = ReportCache(tmp_path)
    generated = generate_report(
        generation_cases[1],
        GEN_NO_RAG,
        client=UnavailableClient(),
        cache=cache,
    )
    assert generated.fallback
    assert "FALLBACK REPORT - LLM unavailable" in generated.report_md
    assert cache.get(GEN_NO_RAG.name, generated.case_id, PROMPT_VERSION) is None
