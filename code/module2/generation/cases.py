"""Serializable alert cases consumed by the report-generation pipeline."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from ..config import AMBIGUOUS_PAIR, CLASS_ORDER

EvidenceScreen = Literal["discriminative", "contextual"]

DEVICE_CATEGORIES = (
    "doorbell",
    "thermostat",
    "baby_monitor",
    "security_camera",
    "webcam",
)


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    feature: str
    value: float
    benign_median: float
    benign_std: float
    benign_p99: float
    screen: EvidenceScreen

    def __post_init__(self) -> None:
        if self.screen not in ("discriminative", "contextual"):
            raise ValueError(f"unknown evidence screen: {self.screen!r}")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceItem":
        return cls(
            feature=str(data["feature"]),
            value=float(data["value"]),
            benign_median=float(data["benign_median"]),
            benign_std=float(data["benign_std"]),
            benign_p99=float(data["benign_p99"]),
            screen=data["screen"],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AlertCase:
    case_id: str
    device_name: str
    device_category: str
    y_pred: str
    p_top1: float
    top2_class: str
    p_top2: float
    p_pair: float
    margin: float
    entropy: float
    evidence: list[EvidenceItem]
    label_type: str | None = None

    def __post_init__(self) -> None:
        if self.device_category not in DEVICE_CATEGORIES:
            raise ValueError(f"unknown device category: {self.device_category!r}")
        if self.y_pred not in CLASS_ORDER:
            raise ValueError(f"unknown predicted class: {self.y_pred!r}")
        if self.top2_class not in CLASS_ORDER:
            raise ValueError(f"unknown second-ranked class: {self.top2_class!r}")
        for item in self.evidence:
            if not isinstance(item, EvidenceItem):
                raise TypeError("evidence entries must be EvidenceItem instances")

    @property
    def is_ambiguous_pair(self) -> bool:
        return {self.y_pred, self.top2_class} == set(AMBIGUOUS_PAIR)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AlertCase":
        return cls(
            case_id=str(data["case_id"]),
            device_name=str(data["device_name"]),
            device_category=str(data["device_category"]),
            y_pred=str(data["y_pred"]),
            p_top1=float(data["p_top1"]),
            top2_class=str(data["top2_class"]),
            p_top2=float(data["p_top2"]),
            p_pair=float(data["p_pair"]),
            margin=float(data["margin"]),
            entropy=float(data["entropy"]),
            evidence=[EvidenceItem.from_dict(item) for item in data["evidence"]],
            label_type=data.get("label_type"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "device_name": self.device_name,
            "device_category": self.device_category,
            "y_pred": self.y_pred,
            "p_top1": self.p_top1,
            "top2_class": self.top2_class,
            "p_top2": self.p_top2,
            "p_pair": self.p_pair,
            "margin": self.margin,
            "entropy": self.entropy,
            "evidence": [item.to_dict() for item in self.evidence],
            "label_type": self.label_type,
        }


def load_cases(path: str | Path) -> list[AlertCase]:
    """Load a JSON array of alert cases."""

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("generation case file must contain a JSON array")
    return [AlertCase.from_dict(item) for item in data]


def save_cases(cases: list[AlertCase], path: str | Path) -> None:
    """Write alert cases as a stable, human-readable JSON array."""

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps([case.to_dict() for case in cases], indent=2) + "\n",
        encoding="utf-8",
    )
