"""Render frozen prompt assets into OpenAI-compatible chat messages."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..retrieval.retrievers import ATTACK_TYPE_DISPLAY_NAMES, RetrievedChunk
from .cases import AlertCase, EvidenceItem
from .registers import Register

_PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


@lru_cache(maxsize=1)
def _load_prompt_assets() -> dict[str, Any]:
    assets: dict[str, Any] = {
        "version": (_PROMPTS_DIR / "version.txt").read_text(encoding="utf-8").strip(),
        "system": (_PROMPTS_DIR / "system.md").read_text(encoding="utf-8").strip(),
        "sections": (_PROMPTS_DIR / "sections.md").read_text(encoding="utf-8").strip(),
        "self_check": (_PROMPTS_DIR / "self_check.md").read_text(encoding="utf-8").strip(),
        "registers": {},
    }
    for register in ("assertive", "hedged_pair", "hedged_generic"):
        assets["registers"][register] = (
            _PROMPTS_DIR / f"register_{register}.md"
        ).read_text(encoding="utf-8").strip()
    assets["evidence_templates"] = json.loads(
        (_PROMPTS_DIR / "evidence_templates.json").read_text(encoding="utf-8")
    )
    return assets


PROMPT_VERSION: str = _load_prompt_assets()["version"]


def _probability(value: float) -> str:
    return _load_prompt_assets()["evidence_templates"]["number_formats"][
        "probability"
    ].format(value)


def format_evidence(evidence: list[EvidenceItem]) -> str:
    """Render evidence with the frozen templates and their number formats."""

    template_data = _load_prompt_assets()["evidence_templates"]
    number_formats = template_data["number_formats"]
    lines: list[str] = []
    for index, item in enumerate(evidence, start=1):
        if item.benign_median == 0:
            ratio_text = "far above" if item.value > 0 else "approximately at"
        else:
            ratio = item.value / item.benign_median
            if 0.8 <= ratio <= 1.25:
                rule = "near"
            elif ratio > 1.25:
                rule = "above"
            else:
                rule = "below"
            ratio_text = template_data["ratio_text_rules"][rule].format(
                ratio=number_formats["ratio"].format(ratio)
            )
        lines.append(
            template_data[item.screen].format(
                index=index,
                feature=item.feature,
                value=number_formats["feature_value"].format(item.value),
                ratio_text=ratio_text,
                benign_median=number_formats["feature_value"].format(
                    item.benign_median
                ),
                p99_relation="above" if item.value > item.benign_p99 else "within",
                benign_p99=number_formats["feature_value"].format(item.benign_p99),
            )
        )
    return "\n".join(lines) if lines else "No evidence items were supplied."


def _register_rules(case: AlertCase, register: Register) -> str:
    values = {
        "p_pair": _probability(case.p_pair),
        "p_top1": _probability(case.p_top1),
        "p_top2": _probability(case.p_top2),
        "margin": _probability(case.margin),
        "attack_display": ATTACK_TYPE_DISPLAY_NAMES[case.y_pred],
        "top1": case.y_pred,
        "top2": case.top2_class,
    }
    return _load_prompt_assets()["registers"][register].format(**values)


def _alert_data(case: AlertCase) -> str:
    return "\n".join(
        (
            "ALERT DATA",
            f"- Device: {case.device_name}",
            f"- Device category: {case.device_category}",
            f"- Predicted class: {case.y_pred} "
            f"({ATTACK_TYPE_DISPLAY_NAMES[case.y_pred]})",
            f"- p_top1: {_probability(case.p_top1)}",
            f"- Second class: {case.top2_class} "
            f"({ATTACK_TYPE_DISPLAY_NAMES[case.top2_class]})",
            f"- p_top2: {_probability(case.p_top2)}",
            f"- p_pair: {_probability(case.p_pair)}",
            f"- Margin: {_probability(case.margin)}",
            f"- Entropy: {_probability(case.entropy)}",
        )
    )


def _context_block(
    chunks_by_section: dict[str, list[RetrievedChunk]] | None,
) -> str:
    if not chunks_by_section or not any(chunks_by_section.values()):
        return ""
    lines = ["CONTEXT"]
    context_index = 1
    for section, chunks in chunks_by_section.items():
        if not chunks:
            continue
        lines.append(f"\n### {section.replace('_', ' ').title()}")
        for chunk in chunks:
            title = chunk.metadata.get("title") or chunk.doc_id
            lines.append(f"[C{context_index}] {title}\n{chunk.text}")
            context_index += 1
    return "\n".join(lines)


def _source_materials(
    case: AlertCase,
    register: Register,
    chunks_by_section: dict[str, list[RetrievedChunk]] | None,
) -> str:
    blocks = [
        _alert_data(case),
        f"EVIDENCE\n{format_evidence(case.evidence)}",
    ]
    context = _context_block(chunks_by_section)
    if context:
        blocks.append(context)
    blocks.extend(
        (
            _register_rules(case, register),
            _load_prompt_assets()["sections"],
        )
    )
    return "\n\n".join(blocks)


def build_messages(
    case: AlertCase,
    register: Register,
    chunks_by_section: dict[str, list[RetrievedChunk]] | None = None,
) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": _load_prompt_assets()["system"]},
        {
            "role": "user",
            "content": _source_materials(case, register, chunks_by_section),
        },
    ]


def build_self_check_messages(
    draft_report: str,
    case: AlertCase,
    register: Register,
    chunks_by_section: dict[str, list[RetrievedChunk]] | None = None,
) -> list[dict[str, str]]:
    content = "\n\n".join(
        (
            _load_prompt_assets()["self_check"],
            _source_materials(case, register, chunks_by_section),
            f"DRAFT REPORT\n{draft_report}",
        )
    )
    return [
        {"role": "system", "content": _load_prompt_assets()["system"]},
        {"role": "user", "content": content},
    ]
