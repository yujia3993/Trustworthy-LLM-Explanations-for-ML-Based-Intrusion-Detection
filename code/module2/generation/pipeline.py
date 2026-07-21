"""End-to-end report-generation orchestration."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

from ..retrieval.retrievers import (
    CONFIG_DENSE,
    CONFIG_FULL,
    RetrievedChunk,
    Retriever,
)
from .cache import ReportCache
from .cases import AlertCase
from .llm_client import LLMClient, LLMUnavailableError, fallback_report
from .prompt_builder import (
    PROMPT_VERSION,
    build_messages,
    build_self_check_messages,
)
from .registers import Register, needs_review, select_register

REPORT_SECTIONS = (
    "threat_assessment",
    "attack_mechanism",
    "observable_indicators",
    "immediate_actions",
    "longer_term_remediation",
    "confidence_notes",
)

RetrievalMode = Literal["none", "dense", "full"]


@dataclass(frozen=True, slots=True)
class GenerationConfig:
    name: str
    retrieval: RetrievalMode
    self_check: bool

    def __post_init__(self) -> None:
        if self.retrieval not in ("none", "dense", "full"):
            raise ValueError(f"unknown generation retrieval mode: {self.retrieval!r}")


GEN_NO_RAG = GenerationConfig("no_rag", "none", False)
GEN_NAIVE_RAG = GenerationConfig("naive_rag", "dense", False)
GEN_FULL_RAG = GenerationConfig("full_rag", "full", False)
GEN_SELF_CHECK = GenerationConfig("self_check", "full", True)


@dataclass(frozen=True, slots=True)
class GeneratedReport:
    case_id: str
    config_name: str
    register: Register
    needs_review: bool
    report_md: str
    prompt_version: str
    from_cache: bool
    fallback: bool
    chunk_ids_by_section: dict[str, list[str]]
    model: str | None


def _retrieve_chunks(
    case: AlertCase,
    gen_config: GenerationConfig,
    retriever: Retriever | None,
) -> dict[str, list[RetrievedChunk]]:
    if gen_config.retrieval == "none":
        return {}
    active_retriever = retriever or Retriever()
    base_config = CONFIG_DENSE if gen_config.retrieval == "dense" else CONFIG_FULL
    retrieval_config = replace(base_config, top_k=3)
    chunks_by_section: dict[str, list[RetrievedChunk]] = {}
    seen: set[str] = set()
    retained = 0
    for section in REPORT_SECTIONS:
        section_chunks: list[RetrievedChunk] = []
        retrieved = active_retriever.retrieve(
            section,
            case.y_pred,
            case.device_category,
            retrieval_config,
        )
        for chunk in retrieved:
            if chunk.chunk_id in seen:
                continue
            seen.add(chunk.chunk_id)
            if retained >= 12:
                continue
            section_chunks.append(chunk)
            retained += 1
        chunks_by_section[section] = section_chunks
    return chunks_by_section


def generate_report(
    case: AlertCase,
    gen_config: GenerationConfig,
    retriever: Retriever | None = None,
    client: LLMClient | None = None,
    cache: ReportCache | None = None,
    use_cache: bool = True,
) -> GeneratedReport:
    """Generate, optionally self-check, and cache one incident report."""

    if client is None:
        raise TypeError("client is required")
    register = select_register(case)
    review = needs_review(case)
    chunks_by_section = _retrieve_chunks(case, gen_config, retriever)
    chunk_ids = {
        section: [chunk.chunk_id for chunk in chunks]
        for section, chunks in chunks_by_section.items()
    }
    messages = build_messages(case, register, chunks_by_section)
    if cache is not None and use_cache:
        entry = cache.get(gen_config.name, case.case_id, PROMPT_VERSION)
        if entry is not None:
            return GeneratedReport(
                case_id=case.case_id,
                config_name=gen_config.name,
                register=register,
                needs_review=review,
                report_md=entry["report_md"],
                prompt_version=PROMPT_VERSION,
                from_cache=True,
                fallback=False,
                chunk_ids_by_section=chunk_ids,
                model=entry.get("model"),
            )

    model = getattr(client, "model", None)
    try:
        report_md = client.complete(messages)
        if gen_config.self_check:
            report_md = client.complete(
                build_self_check_messages(
                    report_md, case, register, chunks_by_section
                )
            )
    except LLMUnavailableError:
        return GeneratedReport(
            case_id=case.case_id,
            config_name=gen_config.name,
            register=register,
            needs_review=review,
            report_md=fallback_report(case, register, chunks_by_section),
            prompt_version=PROMPT_VERSION,
            from_cache=False,
            fallback=True,
            chunk_ids_by_section=chunk_ids,
            model=model,
        )

    if cache is not None and use_cache:
        cache.put(
            report_md=report_md,
            register=register,
            config_name=gen_config.name,
            case_id=case.case_id,
            prompt_version=PROMPT_VERSION,
            model=model,
        )
    return GeneratedReport(
        case_id=case.case_id,
        config_name=gen_config.name,
        register=register,
        needs_review=review,
        report_md=report_md,
        prompt_version=PROMPT_VERSION,
        from_cache=False,
        fallback=False,
        chunk_ids_by_section=chunk_ids,
        model=model,
    )
