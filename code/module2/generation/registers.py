"""Confidence-register selection for generated reports."""

from __future__ import annotations

from typing import Literal

from ..config import REGISTER_THRESHOLD
from .cases import AlertCase

Register = Literal["assertive", "hedged_pair", "hedged_generic"]


def select_register(case: AlertCase) -> Register:
    if case.margin >= REGISTER_THRESHOLD:
        return "assertive"
    if case.is_ambiguous_pair:
        return "hedged_pair"
    return "hedged_generic"


def needs_review(case: AlertCase) -> bool:
    return case.is_ambiguous_pair and case.margin >= REGISTER_THRESHOLD
