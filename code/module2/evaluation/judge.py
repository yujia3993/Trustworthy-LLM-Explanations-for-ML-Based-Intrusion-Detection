"""Independent LLM judge, response validation, and protocol-versioned cache."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Sequence

from ..generation.cases import AlertCase
from ..generation.llm_client import LLMClient, OpenAICompatibleClient
from ..generation.prompt_builder import _alert_data, _context_block, format_evidence
from ..retrieval.retrievers import RetrievedChunk
from .claims import Claim, EvalParseError

_EVALUATION_DIR = Path(__file__).resolve().parent
_PROMPT_PATH = _EVALUATION_DIR / "prompts" / "judge.md"
_RUBRIC_PATH = _EVALUATION_DIR / "judge_rubric.json"
DEFAULT_JUDGE_CACHE_DIR = _EVALUATION_DIR / "judge_cache"


@lru_cache(maxsize=1)
def load_judge_rubric() -> dict[str, Any]:
    return json.loads(_RUBRIC_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _judge_prompt() -> str:
    return _PROMPT_PATH.read_text(encoding="utf-8").strip()


@dataclass(frozen=True, slots=True)
class JudgeResult:
    claim_labels: list[dict[str, str]]
    factual_accuracy: int
    actionability_device_specific: int
    actionability_phases_separated: int
    actionability_matches_category: int
    hallucination_check: int
    comments: str


def _require_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvalParseError(f"judge field {field!r} must be an integer")
    return value


def parse_judge_json(
    raw: str,
    claims: Sequence[Claim] | None = None,
    *,
    expected_claim_count: int | None = None,
) -> JudgeResult:
    """Parse a judge response and validate every frozen enum and range."""

    try:
        value = json.loads(raw.strip())
    except (json.JSONDecodeError, TypeError) as exc:
        detail = getattr(exc, "msg", str(exc))
        raise EvalParseError(f"judge JSON is invalid: {detail}") from exc
    if not isinstance(value, dict):
        raise EvalParseError("judge response must be a JSON object")

    rubric = load_judge_rubric()
    allowed_labels = set(rubric["claim_labels"])
    claim_labels = value.get("claim_labels")
    if not isinstance(claim_labels, list):
        raise EvalParseError("judge field 'claim_labels' must be an array")
    expected = len(claims) if claims is not None else expected_claim_count
    if expected is not None and len(claim_labels) != expected:
        raise EvalParseError(
            f"judge returned {len(claim_labels)} claim labels; expected {expected}"
        )
    parsed_labels: list[dict[str, str]] = []
    for index, item in enumerate(claim_labels):
        if not isinstance(item, dict):
            raise EvalParseError(f"judge claim label {index}: expected an object")
        text = item.get("text")
        label = item.get("label")
        if not isinstance(text, str):
            raise EvalParseError(f"judge claim label {index}: text must be a string")
        if label not in allowed_labels:
            raise EvalParseError(
                f"judge claim label {index}: invalid label {label!r}; "
                f"expected one of {sorted(allowed_labels)}"
            )
        if claims is not None and text != claims[index].text:
            raise EvalParseError(
                f"judge claim label {index}: text does not match the supplied claim"
            )
        parsed_labels.append({"text": text, "label": label})

    scores = rubric["report_scores"]
    parsed_scores: dict[str, int] = {}
    for field in (
        "factual_accuracy",
        "actionability_device_specific",
        "actionability_phases_separated",
        "actionability_matches_category",
        "hallucination_check",
    ):
        if field not in value:
            raise EvalParseError(f"judge response is missing field {field!r}")
        number = _require_integer(value[field], field)
        rule = scores[field]
        if "enum" in rule and number not in rule["enum"]:
            raise EvalParseError(f"judge field {field!r} has invalid value {number}")
        if "min" in rule and number < rule["min"]:
            raise EvalParseError(f"judge field {field!r} is below {rule['min']}")
        if "max" in rule and number > rule["max"]:
            raise EvalParseError(f"judge field {field!r} is above {rule['max']}")
        parsed_scores[field] = number
    comments = value.get("comments")
    if not isinstance(comments, str):
        raise EvalParseError("judge field 'comments' must be a string")

    return JudgeResult(
        claim_labels=parsed_labels,
        factual_accuracy=parsed_scores["factual_accuracy"],
        actionability_device_specific=parsed_scores[
            "actionability_device_specific"
        ],
        actionability_phases_separated=parsed_scores[
            "actionability_phases_separated"
        ],
        actionability_matches_category=parsed_scores[
            "actionability_matches_category"
        ],
        hallucination_check=parsed_scores["hallucination_check"],
        comments=comments,
    )


def _claims_payload(claims: Sequence[Claim]) -> str:
    payload = [
        {
            "text": claim.text,
            "section": claim.section,
            "type": claim.type,
            "cited_refs": claim.cited_refs,
        }
        for claim in claims
    ]
    return json.dumps(payload, ensure_ascii=False, indent=2)


class JudgeClient:
    """Independent judge client using the JUDGE_* endpoint configuration."""

    def __init__(
        self,
        client: LLMClient | None = None,
        cache_dir: str | Path = DEFAULT_JUDGE_CACHE_DIR,
    ) -> None:
        if client is None:
            model = os.environ.get("JUDGE_MODEL") or "gpt-4.1-mini"
            client = OpenAICompatibleClient(
                model=model,
                base_url=os.environ.get("JUDGE_BASE_URL")
                or "https://api.openai.com/v1",
                api_key=os.environ.get("JUDGE_API_KEY", ""),
                temperature=0.0,
            )
        self.client = client
        self.model = str(getattr(client, "model", os.environ.get("JUDGE_MODEL", "unknown")))
        self.cache_dir = Path(cache_dir)

    @staticmethod
    def cache_key(judge_model: str, case_id: str, config_name: str) -> str:
        version = load_judge_rubric()["eval_prompt_version"]
        material = "|".join((judge_model, case_id, config_name, version))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def build_messages(
        self,
        case: AlertCase,
        report_md: str,
        claims: Sequence[Claim],
        chunks_by_section: dict[str, list[RetrievedChunk]] | None = None,
    ) -> list[dict[str, str]]:
        invalid_types = [claim.type for claim in claims if claim.type == "feature"]
        if invalid_types:
            raise ValueError("feature claims must be routed to machine verification")
        blocks = [
            _alert_data(case),
            f"EVIDENCE\n{format_evidence(case.evidence)}",
        ]
        context = _context_block(chunks_by_section)
        if context:
            blocks.append(context)
        blocks.extend((f"REPORT\n{report_md}", f"CLAIMS\n{_claims_payload(claims)}"))
        return [
            {"role": "system", "content": _judge_prompt()},
            {"role": "user", "content": "\n\n".join(blocks)},
        ]

    def judge(
        self,
        case: AlertCase,
        report_md: str,
        claims: Sequence[Claim],
        chunks_by_section: dict[str, list[RetrievedChunk]] | None = None,
        *,
        config_name: str = "unknown",
        use_cache: bool = True,
    ) -> JudgeResult:
        key = self.cache_key(self.model, case.case_id, config_name)
        cache_path = self.cache_dir / f"{key}.json"
        if use_cache and cache_path.exists():
            return parse_judge_json(cache_path.read_text(encoding="utf-8"), claims)

        raw = self.client.complete(
            self.build_messages(case, report_md, claims, chunks_by_section)
        )
        result = parse_judge_json(raw, claims)
        if use_cache:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(
                json.dumps(asdict(result), indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        return result


class MockJudgeClient:
    """Deterministic, non-degenerate offline implementation of the judge rubric."""

    model = "mock-judge"

    def judge(
        self,
        case: AlertCase,
        report_md: str,
        claims: Sequence[Claim],
        chunks_by_section: dict[str, list[RetrievedChunk]] | None = None,
        *,
        config_name: str = "unknown",
        use_cache: bool = True,
    ) -> JudgeResult:
        del case, report_md, chunks_by_section, config_name, use_cache
        labels: list[dict[str, str]] = []
        uncited_knowledge_index = 0
        false_count = 0
        for claim in claims:
            if claim.cited_refs:
                label = "supported"
            else:
                if claim.type == "knowledge":
                    uncited_knowledge_index += 1
                if claim.type == "knowledge" and uncited_knowledge_index % 7 == 0:
                    label = "unsupported_and_false"
                    false_count += 1
                else:
                    label = "unsupported_but_true"
            labels.append({"text": claim.text, "label": label})
        return JudgeResult(
            claim_labels=labels,
            factual_accuracy=4,
            actionability_device_specific=1,
            actionability_phases_separated=1,
            actionability_matches_category=1,
            hallucination_check=false_count,
            comments="mock",
        )
