"""Public API for confidence-aware Module 2 report generation."""

from .audit import AuditResult, audit_report
from .cache import ReportCache
from .cases import AlertCase, EvidenceItem, load_cases, save_cases
from .llm_client import (
    LLMClient,
    LLMUnavailableError,
    MockLLMClient,
    OpenAICompatibleClient,
    fallback_report,
)
from .pipeline import (
    GEN_FULL_RAG,
    GEN_NAIVE_RAG,
    GEN_NO_RAG,
    GEN_SELF_CHECK,
    REPORT_SECTIONS,
    GeneratedReport,
    GenerationConfig,
    generate_report,
)
from .prompt_builder import (
    PROMPT_VERSION,
    build_messages,
    build_self_check_messages,
    format_evidence,
)
from .registers import needs_review, select_register

__all__ = [
    "AlertCase",
    "AuditResult",
    "EvidenceItem",
    "GEN_FULL_RAG",
    "GEN_NAIVE_RAG",
    "GEN_NO_RAG",
    "GEN_SELF_CHECK",
    "GeneratedReport",
    "GenerationConfig",
    "LLMClient",
    "LLMUnavailableError",
    "MockLLMClient",
    "OpenAICompatibleClient",
    "PROMPT_VERSION",
    "REPORT_SECTIONS",
    "ReportCache",
    "audit_report",
    "build_messages",
    "build_self_check_messages",
    "fallback_report",
    "format_evidence",
    "generate_report",
    "load_cases",
    "needs_review",
    "save_cases",
    "select_register",
]
