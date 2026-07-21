"""LLM clients plus deterministic and retrieval-only generation fallbacks."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Protocol

from ..retrieval.retrievers import RetrievedChunk
from .cases import AlertCase
from .prompt_builder import format_evidence
from .registers import Register


class LLMUnavailableError(RuntimeError):
    """Raised when an LLM endpoint cannot service a completion request."""


class LLMClient(Protocol):
    def complete(self, messages: list[dict[str, str]]) -> str:
        """Return the assistant's text response."""


class OpenAICompatibleClient:
    """Minimal dependency-free client for an OpenAI-compatible chat endpoint."""

    def __init__(
        self,
        model: str = "gpt-4.1-mini",
        base_url: str | None = None,
        api_key: str | None = None,
        temperature: float = 0.0,
        timeout: int = 120,
    ) -> None:
        self.model = model
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL") or
                         "https://api.openai.com/v1").rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("OPENAI_API_KEY")
        self.temperature = temperature
        self.timeout = timeout

    def complete(self, messages: list[dict[str, str]]) -> str:
        if not self.api_key:
            raise LLMUnavailableError("OPENAI_API_KEY is not configured")
        payload = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "temperature": self.temperature,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = getattr(response, "status", 200)
                body = response.read().decode("utf-8")
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError) as exc:
            raise LLMUnavailableError(f"LLM request failed: {exc}") from exc
        if status < 200 or status >= 300:
            raise LLMUnavailableError(f"LLM endpoint returned HTTP {status}")
        try:
            result = json.loads(body)
            content = result["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise LLMUnavailableError("LLM endpoint returned an invalid response") from exc
        if not isinstance(content, str):
            raise LLMUnavailableError("LLM endpoint returned non-text content")
        return content


def _prompt_value(prompt: str, label: str) -> str:
    match = re.search(rf"(?m)^- {re.escape(label)}:\s*(.+?)\s*$", prompt)
    if not match:
        raise ValueError(f"mock prompt has no {label!r} field")
    return match.group(1)


class MockLLMClient:
    """Deterministic register-aware client used by offline tests and examples."""

    model = "mock-llm"

    def complete(self, messages: list[dict[str, str]]) -> str:
        prompt = next(
            message["content"] for message in reversed(messages)
            if message["role"] == "user"
        )
        if "REGISTER RULES: HEDGED - AMBIGUOUS PAIR" in prompt:
            return self._hedged_pair(prompt)
        if "REGISTER RULES: HEDGED - GENERIC" in prompt:
            return self._hedged_generic(prompt)
        if "REGISTER RULES: ASSERTIVE" in prompt:
            return self._assertive(prompt)
        raise ValueError("mock could not identify a register block")

    @staticmethod
    def _assertive(prompt: str) -> str:
        predicted = _prompt_value(prompt, "Predicted class")
        attack_display_match = re.search(r"\(([^()]*)\)\s*$", predicted)
        attack_display = (
            attack_display_match.group(1) if attack_display_match else predicted
        )
        probability = _prompt_value(prompt, "p_top1")
        margin = _prompt_value(prompt, "Margin")
        device = _prompt_value(prompt, "Device")
        return f"""## Threat Assessment
This device is emitting {attack_display}. The calibrated probability is {probability}. The affected device is {device}; attacker identity, intent, and dwell time are not established by the available evidence.

## Attack Mechanism
The classifier identifies the traffic class; additional mechanism details are not established by the available evidence.

## Observable Indicators
- Review the supplied evidence observations against the device's benign baseline.

## Immediate Actions
1. Isolate the device from the network while preserving the alert evidence.
2. Inspect gateway traffic and remove unnecessary external exposure.

## Longer-term Remediation
Place the device on a restricted IoT segment, rotate its credentials, and apply supported firmware updates.

## Confidence Notes
The calibrated probability is {probability} and the decision margin is {margin}. Calibration is a statement about long-run error rates, not a guarantee for this individual alert."""

    @staticmethod
    def _hedged_pair(prompt: str) -> str:
        pair_probability = _prompt_value(prompt, "p_pair")
        device = _prompt_value(prompt, "Device")
        return f"""## Threat Assessment
The device {device} is emitting a Gafgyt flood over TCP or UDP (the tcp-or-udp pair), with pair probability {pair_probability}. The candidates gafgyt_tcp and gafgyt_udp cannot be distinguished from the available traffic features because the feature set does not record the transport protocol. The flood victim and the local network are the harmed parties; attacker identity and intent are not established by the available evidence.

## Attack Mechanism
At the supported pair level, the device emits flood traffic associated with gafgyt_tcp and gafgyt_udp. The available evidence does not establish further mechanism details.

## Observable Indicators
- Review each supplied evidence observation against the device's benign baseline; no within-pair assignment is supported.

## Immediate Actions
1. Isolate the device and contain the traffic; containment is identical for gafgyt_tcp and gafgyt_udp and must not wait for disambiguation.
2. After containment, capture any single packet of the flood traffic with tcpdump at the gateway and read the IP header protocol field: protocol 6 means gafgyt_tcp, while protocol 17 means gafgyt_udp.

## Longer-term Remediation
Keep the device on a restricted IoT segment, rotate its credentials, apply supported firmware updates, and remove unnecessary external exposure.

## Confidence Notes
The pair probability is {pair_probability}. The candidates gafgyt_tcp and gafgyt_udp cannot be distinguished from the available traffic features because the feature set does not record the transport protocol. Any within-pair probability split carries no evidential value because it derives from capture artefacts that do not generalise."""

    @staticmethod
    def _hedged_generic(prompt: str) -> str:
        predicted = _prompt_value(prompt, "Predicted class").split(" ", 1)[0]
        second = _prompt_value(prompt, "Second class").split(" ", 1)[0]
        p_top1 = _prompt_value(prompt, "p_top1")
        p_top2 = _prompt_value(prompt, "p_top2")
        margin = _prompt_value(prompt, "Margin")
        device = _prompt_value(prompt, "Device")
        return f"""## Threat Assessment
Identification is uncertain: the classifier cannot reliably distinguish between {predicted} (calibrated probability {p_top1}) and {second} (calibrated probability {p_top2}) for {device}.

## Attack Mechanism
Only mechanisms shared by both candidates should guide action; candidate-specific mechanism details are not established by the available evidence.

## Observable Indicators
- Treat the supplied observations as evidence requiring comparison against both candidates.

## Immediate Actions
1. Isolate the device and preserve traffic evidence, actions valid for both candidates.
2. Review candidate-specific evidence for {predicted} and {second} in separate branches.

## Longer-term Remediation
Segment the device, rotate its credentials, apply supported firmware updates, and remove unnecessary exposure.

## Confidence Notes
The identification remains uncertain: the classifier cannot reliably distinguish between {predicted} (calibrated probability {p_top1}) and {second} (calibrated probability {p_top2}). The decision margin is {margin}; escalate this alert for manual review."""


def _fallback_context(
    chunks_by_section: dict[str, list[RetrievedChunk]] | None,
) -> dict[str, list[tuple[int, RetrievedChunk]]]:
    numbered: dict[str, list[tuple[int, RetrievedChunk]]] = {}
    index = 1
    for section, chunks in (chunks_by_section or {}).items():
        numbered[section] = []
        for chunk in chunks:
            numbered[section].append((index, chunk))
            index += 1
    return numbered


def fallback_report(
    case: AlertCase,
    register: Register,
    chunks_by_section: dict[str, list[RetrievedChunk]] | None,
) -> str:
    """Return source material without synthesizing model-generated analysis."""

    numbered = _fallback_context(chunks_by_section)
    banner = (
        "FALLBACK REPORT - LLM unavailable; contents are retrieved material only, "
        "not model-generated analysis"
    )
    sections = (
        "threat_assessment",
        "attack_mechanism",
        "observable_indicators",
        "immediate_actions",
        "longer_term_remediation",
        "confidence_notes",
    )
    headings = dict(
        zip(
            sections,
            (
                "Threat Assessment",
                "Attack Mechanism",
                "Observable Indicators",
                "Immediate Actions",
                "Longer-term Remediation",
                "Confidence Notes",
            ),
        )
    )
    blocks: list[str] = []
    for section in sections:
        lines = [f"## {headings[section]}"]
        if section == "threat_assessment":
            lines.extend(
                (
                    banner,
                    f"Alert case: `{case.case_id}`; device: `{case.device_name}`; "
                    f"predicted class: `{case.y_pred}`; register: `{register}`.",
                )
            )
        if section == "observable_indicators":
            lines.extend(
                (
                    "| Evidence | Screen | Rendered observation |",
                    "|---|---|---|",
                )
            )
            rendered = format_evidence(case.evidence).splitlines()
            for index, (item, observation) in enumerate(
                zip(case.evidence, rendered), start=1
            ):
                safe_observation = observation.replace("|", "\\|")
                lines.append(f"| E{index} | {item.screen} | {safe_observation} |")
        for index, chunk in numbered.get(section, []):
            title = chunk.metadata.get("title") or chunk.doc_id
            excerpt = chunk.text.strip()
            if len(excerpt) > 800:
                excerpt = excerpt[:797].rstrip() + "..."
            quoted = "\n".join(f"> {line}" for line in excerpt.splitlines())
            lines.append(f"**[C{index}] {title}**\n\n{quoted}")
        if len(lines) == 1:
            lines.append("No retrieved material was available for this section.")
        blocks.append("\n\n".join(lines))
    return "\n\n".join(blocks)
