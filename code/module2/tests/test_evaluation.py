"""Offline tests for the frozen Module 3 evaluation harness."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from ..evaluation.claims import Claim, EvalParseError, MockClaimExtractor, parse_claims_json
from ..evaluation.feature_verify import (
    classify_feature_claim,
    extract_numeric_tokens,
    verify_features,
)
from ..evaluation.judge import JudgeClient, MockJudgeClient, parse_judge_json
from ..evaluation.metrics import cohens_kappa, weighted_kappa
from ..evaluation.run_eval import main as run_eval_main, run_eval
from ..generation import (
    AlertCase,
    EvidenceItem,
    MockLLMClient,
)
from ..retrieval import Retriever


@pytest.fixture(scope="session")
def evaluation_retriever(retrieval_index) -> Retriever:
    index_dir, _ = retrieval_index
    return Retriever(index_dir)


@pytest.fixture
def feature_case() -> AlertCase:
    return AlertCase(
        case_id="feature-case",
        device_name="camera",
        device_category="security_camera",
        y_pred="gafgyt_tcp",
        p_top1=0.61234,
        top2_class="gafgyt_udp",
        p_top2=0.38766,
        p_pair=1.0,
        margin=0.22468,
        entropy=0.66789,
        evidence=[
            EvidenceItem("HH_weight", 20.0, 10.0, 2.0, 15.0, "contextual"),
            EvidenceItem("MI_dir_L3_weight", 30.0, 5.0, 1.5, 12.0, "discriminative"),
            EvidenceItem("HH_L0.1_magnitude", 8.0, 4.0, 0.5, 7.0, "contextual"),
        ],
    )


class _CountingMockLLMClient(MockLLMClient):
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, messages: list[dict[str, str]]) -> str:
        self.calls += 1
        return super().complete(messages)


def test_feature_verification_accepts_case_values_and_probabilities(feature_case):
    report = """## Observable Indicators
HH_weight is 20 against median 10, std 2, and p99 15 (2.0x) [E1].
MI_dir_L3_weight is 30 against 5, 1.5, and 12 (6.0x) [E2].
The probabilities are 0.6123, 0.3877, 1.0000, margin 0.2247, entropy 0.6679.
"""
    result = verify_features(report, feature_case, {})
    assert result.fabricated_numbers == []
    assert {"0.6123", "0.3877", "1.0000", "0.2247", "0.6679"} <= set(
        result.matched_numbers
    )


def test_feature_verification_flags_number_ref_and_contextual_misuse(feature_case):
    report = (
        "HH_weight = 20 [E9] indicates a Gafgyt TCP flood. "
        "The invented score is 987.65."
    )
    result = verify_features(report, feature_case, {})
    assert "987.65" in result.fabricated_numbers
    assert result.invalid_refs == ["[E9]"]
    assert result.contextual_misuse == [
        "HH_weight = 20 [E9] indicates a Gafgyt TCP flood."
    ]


def test_protocol_constants_and_markdown_indices_are_excluded(feature_case):
    report = """## 3. Immediate Actions
1. Capture a pcap with tcpdump: IP protocol 6 is TCP and protocol 17 is UDP.
2. Check Telnet port 23 or 2323, HTTPS port 443, DNS port 53, and NTP UDP port 123.
"""
    assert extract_numeric_tokens(report) == []
    assert verify_features(report, feature_case, {}).fabricated_numbers == []


def test_classify_feature_claim_three_machine_paths(feature_case):
    correct = verify_features("Value 20 [E1].", feature_case, {})
    assert classify_feature_claim(
        Claim("Value 20 [E1].", "observable_indicators", "feature", ["[E1]"]),
        correct,
    ) == "supported"
    assert classify_feature_claim(
        Claim("Value 20.", "observable_indicators", "feature", []), correct
    ) == "unsupported_but_true"
    fabricated = verify_features("Value 999 [E1].", feature_case, {})
    assert classify_feature_claim(
        Claim("Value 999 [E1].", "observable_indicators", "feature", ["[E1]"]),
        fabricated,
    ) == "unsupported_and_false"


def test_parse_claims_json_valid_and_enum_violation():
    raw = json.dumps(
        [
            {
                "text": "A supported-looking claim.",
                "section": "threat_assessment",
                "type": "knowledge",
                "cited_refs": ["[C1]"],
            }
        ]
    )
    assert parse_claims_json(f"  {raw}\n")[0].section == "threat_assessment"
    invalid = json.loads(raw)
    invalid[0]["type"] = "opinion"
    with pytest.raises(EvalParseError, match="invalid type"):
        parse_claims_json(json.dumps(invalid))


def test_parse_claims_json_accepts_fenced_array():
    raw = json.dumps(
        [
            {
                "text": "A fenced claim.",
                "section": "threat_assessment",
                "type": "knowledge",
                "cited_refs": [],
            }
        ]
    )

    assert parse_claims_json(f"```json\n{raw}\n```") == parse_claims_json(raw)


def _judge_json(label: str = "supported", accuracy: int = 5) -> str:
    return json.dumps(
        {
            "claim_labels": [{"text": "claim", "label": label}],
            "factual_accuracy": accuracy,
            "actionability_device_specific": 1,
            "actionability_phases_separated": 1,
            "actionability_matches_category": 1,
            "hallucination_check": 0,
            "comments": "none",
        }
    )


def _judge_json_for_texts(*texts: str) -> str:
    value = json.loads(_judge_json())
    value["claim_labels"] = [
        {"text": text, "label": "supported"} for text in texts
    ]
    return json.dumps(value)


def test_parse_judge_json_valid_and_enum_violation():
    claims = [Claim("claim", "attack_mechanism", "knowledge", [])]
    assert parse_judge_json(_judge_json(), claims).factual_accuracy == 5
    with pytest.raises(EvalParseError, match="invalid label"):
        parse_judge_json(_judge_json("invented"), claims)
    with pytest.raises(EvalParseError, match="above 5"):
        parse_judge_json(_judge_json(accuracy=6), claims)


def test_parse_judge_json_accepts_json_and_unlabelled_fences():
    claims = [Claim("claim", "attack_mechanism", "knowledge", [])]
    raw = _judge_json()
    expected = parse_judge_json(raw, claims)

    assert parse_judge_json(f"```json\n{raw}\n```", claims) == expected
    assert parse_judge_json(f"```\n{raw}\n```", claims) == expected
    assert parse_judge_json(f"  {raw}\n", claims) == expected
    # Providers vary on fence casing and trailing whitespace; none of it is a schema error.
    assert parse_judge_json(f"```JSON \n{raw}\n``` ", claims) == expected


def test_parse_judge_json_rejects_json_surrounded_by_prose():
    with pytest.raises(EvalParseError, match="judge JSON is invalid"):
        parse_judge_json(f"Here is the result:\n{_judge_json()}\nHope that helps.")


@pytest.mark.parametrize(
    ("supplied_text", "returned_text"),
    [
        (
            "exposing the device’s Telnet ports",
            "exposing the device's Telnet ports",
        ),
        (
            "traffic observed during a five–minute window",
            "traffic observed during a five-minute window",
        ),
        ("multiple spaces between words", "  multiple   spaces between words  "),
    ],
)
def test_parse_judge_json_accepts_typographic_and_whitespace_differences(
    supplied_text, returned_text
):
    claims = [Claim(supplied_text, "attack_mechanism", "knowledge", [])]

    result = parse_judge_json(_judge_json_for_texts(returned_text), claims)

    assert result.claim_labels == [{"text": supplied_text, "label": "supported"}]


@pytest.mark.parametrize(
    "returned_text",
    [
        "The camera contacted the command server.",
        "The router contacted",
    ],
)
def test_parse_judge_json_rejects_content_differences(returned_text):
    claims = [
        Claim(
            "The router contacted the command server.",
            "attack_mechanism",
            "knowledge",
            [],
        )
    ]

    with pytest.raises(EvalParseError, match="text does not match the supplied claim"):
        parse_judge_json(_judge_json_for_texts(returned_text), claims)


def test_parse_judge_json_rejects_claims_returned_out_of_order():
    claims = [
        Claim("First claim.", "attack_mechanism", "knowledge", []),
        Claim("Second claim.", "attack_mechanism", "knowledge", []),
    ]

    with pytest.raises(EvalParseError, match="claim label 0: text does not match"):
        parse_judge_json(
            _judge_json_for_texts("Second claim.", "First claim."), claims
        )


def test_parse_judge_json_rejects_case_difference():
    claims = [Claim("Device contacted a server.", "attack_mechanism", "knowledge", [])]

    with pytest.raises(EvalParseError, match="text does not match the supplied claim"):
        parse_judge_json(_judge_json_for_texts("device contacted a server."), claims)


def test_parse_judge_json_identical_text_behavior_is_unchanged():
    claims = [Claim("Identical claim.", "attack_mechanism", "knowledge", [])]

    result = parse_judge_json(_judge_json_for_texts("Identical claim."), claims)

    assert result.claim_labels == [{"text": "Identical claim.", "label": "supported"}]


def test_cohens_kappa_known_values_and_weighted_sanity():
    assert cohens_kappa(["a", "b", "a"], ["a", "b", "a"]) == 1.0
    a = ["yes"] * 10 + ["no"] * 10
    b = ["yes"] * 7 + ["no"] * 3 + ["yes"] * 3 + ["no"] * 7
    assert cohens_kappa(a, b) == pytest.approx(0.4)
    assert weighted_kappa([1, 2, 3, 4, 5], [1, 2, 3, 4, 5]) == 1.0
    assert weighted_kappa([1, 2, 3, 4, 5], [2, 3, 4, 5, 5]) > weighted_kappa(
        [1, 2, 3, 4, 5], [5, 5, 5, 1, 1]
    )


def test_mock_judge_is_deterministic_and_non_degenerate(feature_case):
    claims = [
        Claim(f"claim {index}", "attack_mechanism", "knowledge", [])
        for index in range(1, 8)
    ]
    judge = MockJudgeClient()
    first = judge.judge(feature_case, "report", claims, use_cache=False)
    second = judge.judge(feature_case, "report", claims, use_cache=False)
    assert first == second
    assert first.claim_labels[-1]["label"] == "unsupported_and_false"
    assert first.hallucination_check == 1


def test_run_eval_all_mock_end_to_end(
    evaluation_retriever, tmp_path, monkeypatch
):
    from ..evaluation import run_eval as run_eval_module

    monkeypatch.setattr(run_eval_module, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(run_eval_module, "GENERATION_CACHE_DIR", tmp_path / "cache")
    summary = run_eval(
        split="dev",
        generator_client=MockLLMClient(),
        judge_client=MockJudgeClient(),
        claim_extractor=MockClaimExtractor(),
        retriever=evaluation_retriever,
        use_cache=False,
    )
    assert len(summary) == 4
    assert {row["config"] for row in summary} == {
        "no_rag",
        "naive_rag",
        "full_rag",
        "self_check",
    }
    for filename in (
        "eval_dev_summary.csv",
        "eval_dev_claims.csv",
        "rq2_audit_dev.csv",
    ):
        assert (tmp_path / filename).exists()

    with (tmp_path / "rq2_audit_dev.csv").open(newline="", encoding="utf-8") as handle:
        audits = list(csv.DictReader(handle))
    hedged = [row for row in audits if row["register"] == "hedged_pair"]
    assert hedged
    assert all(row["passed"] == "True" for row in hedged)

    with (tmp_path / "eval_dev_claims.csv").open(newline="", encoding="utf-8") as handle:
        claims = list(csv.DictReader(handle))
    assert claims
    assert {row["verdict_source"] for row in claims} == {"machine", "judge"}
    assert [(row["case_id"], row["config"]) for row in claims] == sorted(
        (row["case_id"], row["config"]) for row in claims
    )


def test_run_eval_limit_is_stratified_and_writes_scratch_manifest(
    evaluation_retriever, tmp_path, monkeypatch
):
    from ..evaluation import run_eval as run_eval_module

    monkeypatch.setattr(run_eval_module, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(run_eval_module, "GENERATION_CACHE_DIR", tmp_path / "cache")
    summary = run_eval(
        split="dev",
        generator_client=MockLLMClient(),
        judge_client=MockJudgeClient(),
        claim_extractor=MockClaimExtractor(),
        retriever=evaluation_retriever,
        use_cache=False,
        limit=1,
    )

    scratch = tmp_path / "scratch"
    expected_paths = (
        scratch / "eval_dev_summary__limit1.csv",
        scratch / "eval_dev_claims__limit1.csv",
        scratch / "rq2_audit_dev__limit1.csv",
        scratch / "run_manifest_dev__limit1.json",
    )
    assert all(path.exists() for path in expected_paths)
    assert not (tmp_path / "eval_dev_summary.csv").exists()

    manifest = json.loads(expected_paths[-1].read_text(encoding="utf-8"))
    expected_fields = {
        "generated_at",
        "split",
        "configs",
        "limit",
        "results_suffix",
        "partial",
        "use_cache",
        "n_cases",
        "case_ids",
        "generator_model",
        "judge_model",
        "prompt_version",
        "eval_prompt_version",
        "case_set_version",
    }
    assert expected_fields <= set(manifest)
    assert manifest["n_cases"] == len(manifest["case_ids"]) == 3
    assert {
        case_id.rsplit("-", 1)[0] for case_id in manifest["case_ids"]
    } == {"assertive_correct", "hedged_pair", "hedged_generic"}
    assert manifest["partial"] is True
    assert manifest["prompt_version"]
    assert all(row["n_cases"] == 3 for row in summary)


def test_run_eval_config_subset_uses_descriptive_scratch_path(
    evaluation_retriever, tmp_path, monkeypatch
):
    from ..evaluation import run_eval as run_eval_module

    monkeypatch.setattr(run_eval_module, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(run_eval_module, "GENERATION_CACHE_DIR", tmp_path / "cache")
    summary = run_eval(
        split="dev",
        configs=["full_rag"],
        generator_client=MockLLMClient(),
        judge_client=MockJudgeClient(),
        claim_extractor=MockClaimExtractor(),
        retriever=evaluation_retriever,
        use_cache=False,
    )

    assert len(summary) == 1
    assert summary[0]["config"] == "full_rag"
    assert (tmp_path / "scratch" / "eval_dev_summary__full_rag.csv").exists()
    assert not (tmp_path / "eval_dev_summary.csv").exists()


def test_run_eval_reuses_generation_cache(tmp_path, monkeypatch):
    from ..evaluation import run_eval as run_eval_module

    results_dir = tmp_path / "results"
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(run_eval_module, "RESULTS_DIR", results_dir)
    monkeypatch.setattr(run_eval_module, "GENERATION_CACHE_DIR", cache_dir)
    client = _CountingMockLLMClient()
    kwargs = {
        "split": "dev",
        "configs": ["no_rag"],
        "generator_client": client,
        "judge_client": MockJudgeClient(),
        "claim_extractor": MockClaimExtractor(),
        "use_cache": True,
        "limit": 1,
    }

    first_summary = run_eval(**kwargs)
    calls_after_first = client.calls
    first_reports = sorted(
        json.loads(path.read_text(encoding="utf-8"))["report_md"]
        for path in cache_dir.glob("*.json")
    )
    second_summary = run_eval(**kwargs)
    second_run_calls = client.calls - calls_after_first
    second_reports = sorted(
        json.loads(path.read_text(encoding="utf-8"))["report_md"]
        for path in cache_dir.glob("*.json")
    )

    assert calls_after_first > 0
    assert second_run_calls == 0
    assert second_reports == first_reports
    assert second_summary == first_summary


def test_run_eval_no_cache_still_calls_generator(tmp_path, monkeypatch):
    from ..evaluation import run_eval as run_eval_module

    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(run_eval_module, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(run_eval_module, "GENERATION_CACHE_DIR", cache_dir)
    client = _CountingMockLLMClient()
    kwargs = {
        "split": "dev",
        "configs": ["no_rag"],
        "generator_client": client,
        "judge_client": MockJudgeClient(),
        "claim_extractor": MockClaimExtractor(),
        "use_cache": False,
        "limit": 1,
    }

    run_eval(**kwargs)
    calls_after_first = client.calls
    run_eval(**kwargs)

    assert calls_after_first > 0
    assert client.calls - calls_after_first == calls_after_first
    assert list(cache_dir.glob("*.json")) == []


def test_judge_cache_key_includes_report_content():
    first = JudgeClient.cache_key("judge", "case", "config", "first report")
    repeated = JudgeClient.cache_key("judge", "case", "config", "first report")
    changed = JudgeClient.cache_key("judge", "case", "config", "changed report")

    assert first == repeated
    assert first != changed


@pytest.mark.parametrize("limit", [0, -1])
def test_run_eval_rejects_non_positive_limit(limit):
    """A negative limit would slice as bucket[:-1] and silently run nearly everything."""

    with pytest.raises(ValueError, match="limit must be >= 1"):
        run_eval(split="dev", limit=limit, generator_client=MockLLMClient())


@pytest.mark.parametrize("limit", ["0", "-1"])
def test_cli_rejects_non_positive_limit(limit):
    with pytest.raises(SystemExit) as excinfo:
        run_eval_main(["--limit", limit, "--mock"])
    assert excinfo.value.code == 2
