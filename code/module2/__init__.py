"""Typed loading contract between the sealed Module 1 and Module 2."""

from .config import AMBIGUOUS_PAIR, CLASS_ORDER, REGISTER_THRESHOLD, RESULTS_DIR
from .contracts import (
    Alert,
    ContractValidationError,
    load_alerts,
    load_benign_reference_stats,
    load_export_schema,
    load_shap_global_profiles,
)

__all__ = [
    "AMBIGUOUS_PAIR",
    "CLASS_ORDER",
    "REGISTER_THRESHOLD",
    "RESULTS_DIR",
    "Alert",
    "ContractValidationError",
    "load_alerts",
    "load_benign_reference_stats",
    "load_export_schema",
    "load_shap_global_profiles",
]
