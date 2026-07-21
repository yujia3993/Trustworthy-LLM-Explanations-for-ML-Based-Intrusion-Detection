"""
Module 1 -> Module 2 export utilities.

This script turns the trained detection pipeline into explanation-ready data:
  - full calibrated probability vectors for attack alerts
  - quantile-binned per-class calibration summaries and reliability plots
  - class x feature-family SHAP profiles
  - per-device benign reference statistics
  - an explain_alert(...) helper that returns the evidence block consumed by
    the explanation layer

It expects the artefacts produced by train_stage_a.py and train_stage_b.py.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import brier_score_loss
from sklearn.metrics import classification_report
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split

from leakage_filters import (
    EPOCH_LIKE_VALUE_THRESHOLD,
    TIME_LEAKAGE_EXCLUDED_FAMILIES,
    feature_family,
)
from train_stage_b import CALIB_FRACTION, RANDOM_STATE, TEST_FRACTION
from train_stage_b import run_stage_a_on_test

logger = logging.getLogger(__name__)

META_COLS = {"device_name", "label_type", "label_binary", "sample_id"}
WEAK_CLASSES = frozenset({"gafgyt_tcp", "gafgyt_udp"})
WEAK_DEVICES = frozenset({
    "SimpleHome_XCS7_1003_WHT_Security_Camera",
    "Provision_PT_737E_Security_Camera",
    "Ennio_Doorbell",
})
EXPLANATION_EXCLUDE_FAMILIES = TIME_LEAKAGE_EXCLUDED_FAMILIES
EPS = 1e-12


def is_explainable_feature(name: str) -> bool:
    """Whether a traffic feature is allowed into Module 2 evidence."""
    return feature_family(name) not in EXPLANATION_EXCLUDE_FAMILIES


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")


def write_csv_with_fallback(df: pd.DataFrame, path: Path, **kwargs: Any) -> Path:
    """Write CSV, falling back to a clean-model suffix if Windows locks the file."""
    try:
        df.to_csv(path, **kwargs)
        return path
    except PermissionError:
        fallback = path.with_name(f"{path.stem}_clean_model{path.suffix}")
        df.to_csv(fallback, **kwargs)
        logger.warning("Could not overwrite %s; saved fallback -> %s", path, fallback)
        return fallback


def write_text_with_fallback(path: Path, text: str, **kwargs: Any) -> Path:
    """Write text, falling back to a clean-model suffix if Windows locks the file."""
    try:
        path.write_text(text, **kwargs)
        return path
    except PermissionError:
        fallback = path.with_name(f"{path.stem}_clean_model{path.suffix}")
        fallback.write_text(text, **kwargs)
        logger.warning("Could not overwrite %s; saved fallback -> %s", path, fallback)
        return fallback


def write_parquet_with_fallback(df: pd.DataFrame, path: Path, **kwargs: Any) -> Path:
    """Write parquet, falling back to a clean-model suffix if Windows locks it."""
    try:
        df.to_parquet(path, **kwargs)
        return path
    except PermissionError:
        fallback = path.with_name(f"{path.stem}_clean_model{path.suffix}")
        df.to_parquet(fallback, **kwargs)
        logger.warning("Could not overwrite %s; saved fallback -> %s", path, fallback)
        return fallback


def savefig_with_fallback(fig: Any, path: Path, **kwargs: Any) -> Path:
    """Save a figure, falling back to a clean-model suffix if Windows locks it."""
    try:
        fig.savefig(path, **kwargs)
        return path
    except PermissionError:
        fallback = path.with_name(f"{path.stem}_clean_model{path.suffix}")
        fig.savefig(fallback, **kwargs)
        logger.warning("Could not overwrite %s; saved fallback -> %s", path, fallback)
        return fallback


def is_weak_combo(device_name: str, label_type: str) -> bool:
    """Weak RQ2 slice: true gafgyt tcp/udp samples on the weak LODO devices."""
    return device_name in WEAK_DEVICES and label_type in WEAK_CLASSES


def tcp_udp_class_indices(label_encoder: Any) -> tuple[int, int]:
    """Return the fixed gafgyt tcp/udp positions in the saved class order."""
    class_names = label_encoder.classes_
    missing = [name for name in WEAK_CLASSES if name not in class_names]
    if missing:
        raise ValueError(f"Saved Stage B classes are missing tcp/udp: {missing}")
    return (
        int(np.where(class_names == "gafgyt_tcp")[0][0]),
        int(np.where(class_names == "gafgyt_udp")[0][0]),
    )


def validate_clean_stage_a_features(models_dir: Path) -> list[str]:
    """Refuse to label production alerts with a Stage A time-leakage feature."""
    if_features = joblib.load(models_dir / "if_feature_cols.joblib")
    forbidden = [
        feature for feature in if_features
        if feature_family(feature) in TIME_LEAKAGE_EXCLUDED_FAMILIES
    ]
    if forbidden:
        raise RuntimeError(
            "Stage A artefact still contains excluded timestamp-like features: "
            + ", ".join(forbidden)
        )
    return list(if_features)


def entropy_nats(probs: np.ndarray) -> np.ndarray:
    """Shannon entropy in nats for each probability vector."""
    clipped = np.clip(probs, EPS, 1.0)
    return -(clipped * np.log(clipped)).sum(axis=1)


def load_artifacts(models_dir: Path) -> dict[str, Any]:
    calibrated = joblib.load(models_dir / "xgb_stage_b.joblib")
    label_encoder = joblib.load(models_dir / "xgb_label_encoder.joblib")
    feature_cols = joblib.load(models_dir / "xgb_feature_cols.joblib")
    raw_model = get_raw_estimator(calibrated)
    return {
        "calibrated": calibrated,
        "raw_model": raw_model,
        "label_encoder": label_encoder,
        "feature_cols": feature_cols,
    }


def get_raw_estimator(calibrated: Any) -> Any:
    """
    Extract the pre-calibration XGBoost model from CalibratedClassifierCV.

    sklearn has changed the attribute names around prefit calibration across
    versions, so this intentionally checks the known locations.
    """
    for attr in ("estimator", "base_estimator"):
        estimator = getattr(calibrated, attr, None)
        if estimator is not None:
            return estimator

    calibrated_classifiers = getattr(calibrated, "calibrated_classifiers_", None)
    if calibrated_classifiers:
        first = calibrated_classifiers[0]
        for attr in ("estimator", "base_estimator", "classifier"):
            estimator = getattr(first, attr, None)
            if estimator is not None:
                return estimator

    raise AttributeError(
        "Could not find the raw estimator inside xgb_stage_b.joblib. "
        "Expected a fitted CalibratedClassifierCV produced by train_stage_b.py."
    )


def prepare_stage_b_features(
    df: pd.DataFrame,
    expected_feature_cols: list[str],
) -> pd.DataFrame:
    """
    Rebuild the Stage B matrix and align it to the saved training column order.

    Missing device dummy columns are filled with zero; unexpected columns are
    ignored. This keeps inference stable for slices and individual alerts.
    """
    expected_traffic_cols = [
        c for c in expected_feature_cols if not c.startswith("dev_")
    ]
    missing_traffic = [c for c in expected_traffic_cols if c not in df.columns]
    if missing_traffic:
        preview = ", ".join(missing_traffic[:5])
        raise ValueError(
            "Input is missing Stage B traffic features required for inference: "
            f"{preview}"
        )

    device_dummies = pd.get_dummies(df["device_name"], prefix="dev")
    X = pd.concat(
        [df[expected_traffic_cols], device_dummies],
        axis=1,
    )

    for col in expected_feature_cols:
        if col not in X.columns:
            X[col] = 0

    return X[expected_feature_cols]


def top2_from_probs(
    probs: np.ndarray,
    class_names: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    order = np.argsort(-probs, axis=1)
    top1_idx = order[:, 0]
    top2_idx = order[:, 1]
    p_top1 = probs[np.arange(len(probs)), top1_idx]
    p_top2 = probs[np.arange(len(probs)), top2_idx]
    return top1_idx, class_names[top1_idx], p_top1, class_names[top2_idx], p_top2


def export_benign_reference_stats(
    df: pd.DataFrame,
    traffic_feature_cols: list[str],
    out_path: Path,
) -> pd.DataFrame:
    benign = df[df["label_binary"] == 0]
    ref = benign.groupby("device_name")[traffic_feature_cols].agg(
        ["median", "std", ("p99", lambda s: s.quantile(0.99))]
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    write_parquet_with_fallback(ref, out_path)
    logger.info("Saved benign reference stats -> %s", out_path)
    return ref


def export_feature_leakage_audit(
    df: pd.DataFrame,
    results_dir: Path,
) -> pd.DataFrame:
    rows = []
    for feature in traffic_feature_cols_from_df(df):
        values = df[feature].to_numpy(dtype=float)
        median = float(np.nanmedian(values))
        p99 = float(np.nanquantile(values, 0.99))
        max_value = float(np.nanmax(values))
        family = feature_family(feature)
        epoch_like = (
            abs(median) >= EPOCH_LIKE_VALUE_THRESHOLD
            or abs(p99) >= EPOCH_LIKE_VALUE_THRESHOLD
            or abs(max_value) >= EPOCH_LIKE_VALUE_THRESHOLD
        )
        rows.append({
            "feature": feature,
            "feature_family": family,
            "median": median,
            "p99": p99,
            "max": max_value,
            "epoch_like_value": bool(epoch_like),
            "excluded_from_explanation": bool(not is_explainable_feature(feature)),
            "exclude_reason": "excluded_family"
            if family in EXPLANATION_EXCLUDE_FAMILIES
            else ("epoch_like_value_audit_only" if epoch_like else ""),
        })

    audit = pd.DataFrame(rows).sort_values(
        ["excluded_from_explanation", "epoch_like_value", "feature_family", "feature"],
        ascending=[False, False, True, True],
    )
    out_path = results_dir / "feature_leakage_audit.csv"
    write_csv_with_fallback(audit, out_path, index=False)
    logger.info("Saved feature leakage audit -> %s", out_path)
    return audit


def export_alerts_full(
    df: pd.DataFrame,
    X: pd.DataFrame,
    calibrated: Any,
    raw_model: Any,
    label_encoder: Any,
    models_dir: Path,
    results_dir: Path,
) -> pd.DataFrame:
    class_names = label_encoder.classes_
    tcp_idx, udp_idx = tcp_udp_class_indices(label_encoder)
    probs = calibrated.predict_proba(X)
    raw_probs = raw_model.predict_proba(X)
    flip_rate = float((probs.argmax(axis=1) != raw_probs.argmax(axis=1)).mean())

    flip_path = results_dir / "calibration_argmax_flip_check.json"
    write_text_with_fallback(
        flip_path,
        json.dumps({"argmax_flip_rate": flip_rate}, indent=2),
        encoding="utf-8",
    )
    logger.info("Calibration argmax flip rate: %.6f", flip_rate)

    _, y_pred, p_top1, top2_class, p_top2 = top2_from_probs(probs, class_names)

    clean_stage_a_features = validate_clean_stage_a_features(models_dir)
    stage_a_input = df.reset_index(drop=True)
    stage_a_flags = run_stage_a_on_test(stage_a_input, models_dir)

    alerts = pd.DataFrame({
        "sample_id": df["sample_id"].to_numpy()
        if "sample_id" in df.columns else df.index.to_numpy(),
        "device_name": df["device_name"].to_numpy(),
        "y_pred": y_pred,
        "p_vector": [row.astype(float).tolist() for row in probs],
        "p_top1": p_top1.astype(float),
        "top2_class": top2_class,
        "p_top2": p_top2.astype(float),
        "p_pair": (probs[:, tcp_idx] + probs[:, udp_idx]).astype(float),
        "margin": (p_top1 - p_top2).astype(float),
        "entropy": entropy_nats(probs).astype(float),
        "stage_a_flagged": stage_a_flags.astype(bool),
        "is_weak_combo": [
            is_weak_combo(device, label_type)
            for device, label_type in zip(
                df["device_name"].to_numpy(), df["label_type"].to_numpy()
            )
        ],
    })

    attack_alerts = alerts[df["label_binary"].to_numpy() == 1].reset_index(drop=True)
    out_path = results_dir / "alerts_full.parquet"
    write_parquet_with_fallback(attack_alerts, out_path, index=False)
    stage_a_audit = {
        "stage_a_feature_count": len(clean_stage_a_features),
        "stage_a_excluded_time_feature_families": sorted(
            TIME_LEAKAGE_EXCLUDED_FAMILIES
        ),
        "stage_a_flagged_n_all_samples": int(stage_a_flags.sum()),
        "stage_a_flagged_frac_all_samples": float(stage_a_flags.mean()),
        "stage_a_flagged_n_attack_alerts": int(
            attack_alerts["stage_a_flagged"].sum()
        ),
        "stage_a_flagged_frac_attack_alerts": float(
            attack_alerts["stage_a_flagged"].mean()
        ),
    }
    write_text_with_fallback(
        results_dir / "stage_a_alert_metadata.json",
        json.dumps(stage_a_audit, indent=2),
        encoding="utf-8",
    )
    logger.info("Saved %d attack alerts -> %s", len(attack_alerts), out_path)
    return attack_alerts


def export_schema_metadata(label_encoder: Any, results_dir: Path) -> None:
    metadata = {
        "alerts_full_schema": [
            "sample_id",
            "device_name",
            "y_pred",
            "p_vector",
            "p_top1",
            "top2_class",
            "p_top2",
            "p_pair",
            "margin",
            "entropy",
            "stage_a_flagged",
            "is_weak_combo",
        ],
        "p_vector_class_order": list(label_encoder.classes_),
        "p_pair": (
            "Calibrated p(gafgyt_tcp) + p(gafgyt_udp); this is the "
            "tcp-or-udp superclass probability."
        ),
        "entropy": "Shannon entropy over p_vector, natural-log units (nats).",
        "stage_a_flagged": (
            "Boolean clean Stage A Isolation Forest result; its saved feature "
            "list is validated to exclude timestamp-like HH_jit_mean features."
        ),
        "is_weak_combo": {
            "label_type_values": sorted(WEAK_CLASSES),
            "device_names": sorted(WEAK_DEVICES),
        },
        "explanation_feature_filter": {
            "excluded_families": sorted(EXPLANATION_EXCLUDE_FAMILIES),
            "note": "Filtered from Module 2 evidence; model inputs remain unchanged.",
        },
    }
    out_path = results_dir / "module1_export_schema.json"
    write_text_with_fallback(
        out_path, json.dumps(metadata, indent=2), encoding="utf-8"
    )
    logger.info("Saved Module 1 export schema metadata -> %s", out_path)


def quantile_calibration_bins(
    y_binary: np.ndarray,
    prob: np.ndarray,
    n_bins: int,
    min_bin_size: int,
) -> tuple[pd.DataFrame, float]:
    """Equal-frequency calibration bins and ECE."""
    n = len(prob)
    if n == 0:
        empty = pd.DataFrame(columns=[
            "bin", "n", "prob_min", "prob_max", "mean_confidence",
            "empirical_rate", "abs_gap", "ece_contribution",
            "ci95_low", "ci95_high", "is_sparse",
        ])
        return empty, np.nan

    order = np.argsort(prob, kind="mergesort")
    chunks = [idx for idx in np.array_split(order, min(n_bins, n)) if len(idx)]

    rows = []
    for bin_idx, idx in enumerate(chunks):
        bin_prob = prob[idx]
        bin_y = y_binary[idx]
        empirical = float(bin_y.mean())
        confidence = float(bin_prob.mean())
        gap = abs(empirical - confidence)
        se = math.sqrt(max(empirical * (1.0 - empirical), 0.0) / len(idx))
        rows.append({
            "bin": bin_idx,
            "n": int(len(idx)),
            "prob_min": float(bin_prob.min()),
            "prob_max": float(bin_prob.max()),
            "mean_confidence": confidence,
            "empirical_rate": empirical,
            "abs_gap": float(gap),
            "ece_contribution": float((len(idx) / n) * gap),
            "ci95_low": float(max(0.0, empirical - 1.96 * se)),
            "ci95_high": float(min(1.0, empirical + 1.96 * se)),
            "is_sparse": bool(len(idx) < min_bin_size),
        })

    bins = pd.DataFrame(rows)
    return bins, float(bins["ece_contribution"].sum())


def plot_reliability(
    bins: pd.DataFrame,
    class_name: str,
    brier: float,
    ece: float,
    out_path: Path,
) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(5.5, 5.0))
    ax.plot([0, 1], [0, 1], color="black", linestyle="--", linewidth=1)

    if not bins.empty:
        colors = np.where(bins["is_sparse"].to_numpy(), "#9ca3af", "#2563eb")
        yerr = np.vstack([
            bins["empirical_rate"].to_numpy() - bins["ci95_low"].to_numpy(),
            bins["ci95_high"].to_numpy() - bins["empirical_rate"].to_numpy(),
        ])
        ax.errorbar(
            bins["mean_confidence"],
            bins["empirical_rate"],
            yerr=yerr,
            fmt="none",
            ecolor="#94a3b8",
            elinewidth=1,
            capsize=2,
            zorder=1,
        )
        ax.scatter(
            bins["mean_confidence"],
            bins["empirical_rate"],
            s=np.clip(bins["n"].to_numpy(), 20, 240),
            c=colors,
            edgecolor="white",
            linewidth=0.7,
            zorder=2,
        )

    ax.set_title(f"{class_name} reliability")
    ax.set_xlabel("Mean calibrated probability")
    ax.set_ylabel("Empirical positive rate")
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    ax.text(
        0.04, 0.96,
        f"ECE={ece:.4f}\nBrier={brier:.4f}",
        transform=ax.transAxes,
        va="top",
        bbox={"facecolor": "white", "edgecolor": "#cbd5e1", "alpha": 0.9},
    )
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    savefig_with_fallback(fig, out_path, dpi=160)
    plt.close(fig)


def export_calibration_summary(
    df: pd.DataFrame,
    probs: np.ndarray,
    label_encoder: Any,
    results_dir: Path,
    n_bins: int,
    min_bin_size: int,
) -> None:
    out_dir = results_dir / "calibration_summary"
    plot_dir = out_dir / "reliability_plots"
    out_dir.mkdir(parents=True, exist_ok=True)
    plot_dir.mkdir(parents=True, exist_ok=True)

    y_true = label_encoder.transform(df["label_type"].to_numpy())
    class_names = label_encoder.classes_
    summary_rows = []
    all_bins = []

    for class_idx, class_name in enumerate(class_names):
        y_binary = (y_true == class_idx).astype(int)
        class_prob = probs[:, class_idx]
        bins, ece = quantile_calibration_bins(
            y_binary, class_prob, n_bins=n_bins, min_bin_size=min_bin_size
        )
        brier = float(brier_score_loss(y_binary, class_prob))
        bins.insert(0, "class", class_name)
        all_bins.append(bins)
        summary_rows.append({
            "class": class_name,
            "ece_quantile": ece,
            "brier": brier,
            "n_samples": int(len(df)),
            "n_positive": int(y_binary.sum()),
            "n_bins": int(len(bins)),
            "min_bin_size": int(min_bin_size),
        })
        plot_reliability(
            bins,
            class_name,
            brier,
            ece,
            plot_dir / f"{_safe_name(class_name)}.png",
        )

    summary_df = pd.DataFrame(summary_rows)
    bins_df = pd.concat(all_bins, ignore_index=True)
    write_csv_with_fallback(
        summary_df, out_dir / "per_class_calibration.csv", index=False
    )
    write_csv_with_fallback(
        bins_df, out_dir / "per_class_calibration_bins.csv", index=False
    )

    export_weak_combo_calibration(
        df=df,
        probs=probs,
        label_encoder=label_encoder,
        out_dir=out_dir,
        n_bins=n_bins,
        min_bin_size=min_bin_size,
    )
    logger.info("Saved calibration summary -> %s", out_dir)


def export_tcp_udp_pair_calibration(
    df: pd.DataFrame,
    probs: np.ndarray,
    label_encoder: Any,
    results_dir: Path,
    n_bins: int,
    min_bin_size: int,
) -> None:
    """Check the calibrated tcp-or-udp superclass probability on held-out data."""
    out_dir = results_dir / "calibration_summary"
    tcp_idx, udp_idx = tcp_udp_class_indices(label_encoder)
    y_true = label_encoder.transform(df["label_type"].to_numpy())
    y_pair = np.isin(y_true, [tcp_idx, udp_idx]).astype(int)
    p_pair = probs[:, tcp_idx] + probs[:, udp_idx]
    bins, ece = quantile_calibration_bins(
        y_pair,
        p_pair,
        n_bins=n_bins,
        min_bin_size=min_bin_size,
    )
    brier = float(brier_score_loss(y_pair, p_pair))
    summary = pd.DataFrame([{
        "target": "gafgyt_tcp_or_udp",
        "n_samples": int(len(y_pair)),
        "n_positive": int(y_pair.sum()),
        "prevalence": float(y_pair.mean()),
        "ece_quantile": float(ece),
        "brier": brier,
        "min_probability": float(p_pair.min()),
        "max_probability": float(p_pair.max()),
    }])
    bins = bins.assign(target="gafgyt_tcp_or_udp")
    write_csv_with_fallback(
        summary, out_dir / "tcp_udp_pair_calibration.csv", index=False
    )
    write_csv_with_fallback(
        bins, out_dir / "tcp_udp_pair_calibration_bins.csv", index=False
    )
    plot_reliability(
        bins=bins,
        class_name="gafgyt_tcp_or_udp",
        brier=brier,
        ece=ece,
        out_path=out_dir / "reliability_plots" / "gafgyt_tcp_or_udp.png",
    )
    logger.info("Saved tcp/udp pair calibration -> %s", out_dir)


def export_weak_combo_calibration(
    df: pd.DataFrame,
    probs: np.ndarray,
    label_encoder: Any,
    out_dir: Path,
    n_bins: int,
    min_bin_size: int,
) -> None:
    class_names = label_encoder.classes_
    y_true = label_encoder.transform(df["label_type"].to_numpy())
    weak_devices = df["device_name"].isin(WEAK_DEVICES).to_numpy()
    weak_labels = df["label_type"].isin(WEAK_CLASSES).to_numpy()
    weak_mask = weak_devices & weak_labels

    rows = []
    bins_all = []
    for class_name in sorted(WEAK_CLASSES):
        if class_name not in class_names:
            continue
        class_idx = int(np.where(class_names == class_name)[0][0])
        y_slice = (y_true[weak_mask] == class_idx).astype(int)
        p_slice = probs[weak_mask, class_idx]
        bins, ece = quantile_calibration_bins(
            y_slice, p_slice, n_bins=n_bins, min_bin_size=min_bin_size
        )
        brier = (
            float(brier_score_loss(y_slice, p_slice))
            if len(y_slice) else np.nan
        )
        bins.insert(0, "class", class_name)
        bins.insert(0, "slice", "weak_devices_true_gafgyt_tcp_udp")
        bins_all.append(bins)
        rows.append({
            "slice": "weak_devices_true_gafgyt_tcp_udp",
            "class": class_name,
            "ece_quantile": ece,
            "brier": brier,
            "n_samples": int(len(y_slice)),
            "n_positive": int(y_slice.sum()) if len(y_slice) else 0,
            "n_bins": int(len(bins)),
        })

    write_csv_with_fallback(
        pd.DataFrame(rows), out_dir / "weak_combo_calibration.csv", index=False
    )
    if bins_all:
        write_csv_with_fallback(
            pd.concat(bins_all, ignore_index=True),
            out_dir / "weak_combo_calibration_bins.csv",
            index=False,
        )


def reconstruct_stage_b_split_indices(
    df: pd.DataFrame,
    label_encoder: Any,
) -> dict[str, np.ndarray]:
    """Rebuild train/calibration/test indices from train_stage_b.py settings."""
    y = label_encoder.transform(df["label_type"].to_numpy())
    indices = np.arange(len(df))
    trainval_idx, test_idx, y_trainval, _ = train_test_split(
        indices,
        y,
        test_size=TEST_FRACTION,
        stratify=y,
        random_state=RANDOM_STATE,
    )
    train_idx, calib_idx, _, _ = train_test_split(
        trainval_idx,
        y_trainval,
        test_size=CALIB_FRACTION,
        stratify=y_trainval,
        random_state=RANDOM_STATE,
    )
    return {
        "train": np.asarray(train_idx),
        "calib": np.asarray(calib_idx),
        "test": np.asarray(test_idx),
    }


def verify_reconstructed_test_split(
    df: pd.DataFrame,
    X: pd.DataFrame,
    calibrated: Any,
    label_encoder: Any,
    test_idx: np.ndarray,
    results_dir: Path,
) -> dict[str, Any]:
    """Compare rebuilt test metrics with the saved Stage B standalone report."""
    y_test = label_encoder.transform(df.iloc[test_idx]["label_type"].to_numpy())
    probs = calibrated.predict_proba(X.iloc[test_idx])
    preds = probs.argmax(axis=1)
    report = classification_report(
        y_test,
        preds,
        labels=range(len(label_encoder.classes_)),
        target_names=label_encoder.classes_,
        output_dict=True,
        zero_division=0,
    )

    saved_path = results_dir / "stage_b_standalone_report.csv"
    saved = pd.read_csv(saved_path, index_col=0) if saved_path.exists() else None
    checks: dict[str, Any] = {
        "test_fraction": TEST_FRACTION,
        "calib_fraction": CALIB_FRACTION,
        "random_state": RANDOM_STATE,
        "n_test": int(len(test_idx)),
        "recomputed_accuracy": float(report["accuracy"]),
        "recomputed_macro_f1": float(report["macro avg"]["f1-score"]),
        "saved_report_found": saved is not None,
    }
    if saved is not None:
        checks.update({
            "saved_accuracy": float(saved.loc["accuracy", "f1-score"]),
            "saved_macro_f1": float(saved.loc["macro avg", "f1-score"]),
        })
        checks["accuracy_abs_diff"] = abs(
            checks["recomputed_accuracy"] - checks["saved_accuracy"]
        )
        checks["macro_f1_abs_diff"] = abs(
            checks["recomputed_macro_f1"] - checks["saved_macro_f1"]
        )
        checks["matches_saved_report"] = (
            checks["accuracy_abs_diff"] < 1e-12
            and checks["macro_f1_abs_diff"] < 1e-12
        )

    out_path = results_dir / "stage_b_reconstructed_split_check.json"
    write_text_with_fallback(
        out_path, json.dumps(checks, indent=2), encoding="utf-8"
    )
    logger.info("Saved reconstructed split check -> %s", out_path)
    return checks


def export_margin_band_summary(alerts: pd.DataFrame, results_dir: Path) -> pd.DataFrame:
    bins = pd.cut(
        alerts["margin"],
        [0.0, 0.5, 0.9, 0.99, 1.0],
        include_lowest=True,
    )
    summary = (
        alerts.groupby(bins, observed=False)
              .agg(
                  n=("sample_id", "size"),
                  weak_frac=("is_weak_combo", "mean"),
                  mean_entropy=("entropy", "mean"),
                  mean_p_top1=("p_top1", "mean"),
              )
              .reset_index()
              .rename(columns={"margin": "margin_bin"})
    )
    out_path = results_dir / "margin_band_summary.csv"
    write_csv_with_fallback(summary, out_path, index=False)
    logger.info("Saved margin band summary -> %s", out_path)
    return summary


def _margin_bands(values: pd.Series | np.ndarray) -> pd.Categorical:
    return pd.cut(
        values,
        [0.0, 0.5, 0.9, 0.99, 1.0],
        include_lowest=True,
    )


def export_tcp_udp_confusion_margin_summary(
    df: pd.DataFrame,
    X: pd.DataFrame,
    calibrated: Any,
    label_encoder: Any,
    models_dir: Path,
    test_idx: np.ndarray,
    results_dir: Path,
) -> pd.DataFrame:
    """Locate held-out gated gafgyt_tcp -> gafgyt_udp errors by margin band."""
    test_df = df.iloc[test_idx].reset_index(drop=True)
    X_test = X.iloc[test_idx].reset_index(drop=True)
    probs = calibrated.predict_proba(X_test)
    preds = probs.argmax(axis=1)
    y_true = label_encoder.transform(test_df["label_type"].to_numpy())
    class_names = label_encoder.classes_
    tcp_idx = int(np.where(class_names == "gafgyt_tcp")[0][0])
    udp_idx = int(np.where(class_names == "gafgyt_udp")[0][0])

    order = np.argsort(-probs, axis=1)
    p_top1 = probs[np.arange(len(probs)), order[:, 0]]
    p_top2 = probs[np.arange(len(probs)), order[:, 1]]
    margin = p_top1 - p_top2

    stage_a_flags = run_stage_a_on_test(test_df, models_dir)
    error_mask = (y_true == tcp_idx) & (preds == udp_idx) & stage_a_flags

    detail = pd.DataFrame({
        "sample_id": test_df.loc[error_mask, "sample_id"].to_numpy()
        if "sample_id" in test_df.columns else test_df.index[error_mask],
        "device_name": test_df.loc[error_mask, "device_name"].to_numpy(),
        "true_class": "gafgyt_tcp",
        "pred_class": "gafgyt_udp",
        "p_tcp": probs[error_mask, tcp_idx],
        "p_udp": probs[error_mask, udp_idx],
        "margin": margin[error_mask],
    })
    detail["margin_bin"] = _margin_bands(detail["margin"]).astype(str)

    detail_path = results_dir / "tcp_udp_gated_misclassifications.parquet"
    write_parquet_with_fallback(detail, detail_path, index=False)

    summary = (
        detail.groupby("margin_bin", observed=False)
              .agg(
                  n=("sample_id", "size"),
                  mean_margin=("margin", "mean"),
                  mean_p_tcp=("p_tcp", "mean"),
                  mean_p_udp=("p_udp", "mean"),
              )
              .reset_index()
    )
    summary_path = results_dir / "tcp_udp_gated_misclassification_margin.csv"
    write_csv_with_fallback(summary, summary_path, index=False)
    logger.info("Saved tcp->udp margin summary -> %s", summary_path)
    return summary


def _cohens_d(a: np.ndarray, b: np.ndarray) -> float:
    var_a = np.var(a, ddof=1)
    var_b = np.var(b, ddof=1)
    pooled = math.sqrt((var_a + var_b) / 2.0)
    if pooled <= EPS:
        return np.nan
    return float((np.mean(b) - np.mean(a)) / pooled)


def export_tcp_udp_feature_separation(
    df: pd.DataFrame,
    train_idx: np.ndarray,
    results_dir: Path,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Compute direct class-conditional feature differences for gafgyt_tcp vs
    gafgyt_udp on the training split.

    This is intentionally separate from SHAP: it finds discriminative
    tcp-vs-udp evidence even when both classes rely on similar global families.
    """
    train_df = df.iloc[train_idx]
    pair_df = train_df[train_df["label_type"].isin(["gafgyt_tcp", "gafgyt_udp"])]
    tcp_df = pair_df[pair_df["label_type"] == "gafgyt_tcp"]
    udp_df = pair_df[pair_df["label_type"] == "gafgyt_udp"]
    feature_cols = explainable_traffic_feature_cols_from_df(df)

    y_udp = (pair_df["label_type"] == "gafgyt_udp").astype(int).to_numpy()
    rows = []
    for feature in feature_cols:
        values = pair_df[feature].to_numpy(dtype=float)
        tcp_values = tcp_df[feature].to_numpy(dtype=float)
        udp_values = udp_df[feature].to_numpy(dtype=float)

        if np.nanstd(values) <= EPS:
            auc = np.nan
        else:
            auc = float(roc_auc_score(y_udp, values))
        auc_separation = (
            float(max(auc, 1.0 - auc)) if not np.isnan(auc) else np.nan
        )

        tcp_mean = float(np.nanmean(tcp_values))
        udp_mean = float(np.nanmean(udp_values))
        tcp_std = float(np.nanstd(tcp_values, ddof=1))
        udp_std = float(np.nanstd(udp_values, ddof=1))
        tcp_var = float(np.nanvar(tcp_values, ddof=1))
        udp_var = float(np.nanvar(udp_values, ddof=1))
        std_ratio = udp_std / tcp_std if tcp_std > EPS else np.nan
        variance_ratio = udp_var / tcp_var if tcp_var > EPS else np.nan
        abs_log_std_ratio = (
            float(abs(math.log(std_ratio)))
            if std_ratio > EPS and np.isfinite(std_ratio) else np.nan
        )

        rows.append({
            "feature": feature,
            "feature_family": feature_family(feature),
            "n_tcp": int(len(tcp_values)),
            "n_udp": int(len(udp_values)),
            "tcp_mean": tcp_mean,
            "udp_mean": udp_mean,
            "mean_diff_udp_minus_tcp": udp_mean - tcp_mean,
            "tcp_std": tcp_std,
            "udp_std": udp_std,
            "std_ratio_udp_over_tcp": std_ratio,
            "tcp_variance": tcp_var,
            "udp_variance": udp_var,
            "variance_ratio_udp_over_tcp": variance_ratio,
            "abs_log_std_ratio": abs_log_std_ratio,
            "higher_spread_class": "gafgyt_udp"
            if std_ratio > 1.0 else "gafgyt_tcp",
            "tcp_median": float(np.nanmedian(tcp_values)),
            "udp_median": float(np.nanmedian(udp_values)),
            "tcp_p90": float(np.nanquantile(tcp_values, 0.90)),
            "udp_p90": float(np.nanquantile(udp_values, 0.90)),
            "auc_udp_vs_tcp": auc,
            "auc_separation": auc_separation,
            "higher_value_class": "gafgyt_udp"
            if not np.isnan(auc) and auc >= 0.5 else "gafgyt_tcp",
            "cohens_d_udp_minus_tcp": _cohens_d(tcp_values, udp_values),
        })

    concrete = pd.DataFrame(rows).sort_values(
        ["auc_separation", "feature"], ascending=[False, True]
    )
    concrete_path = results_dir / "tcp_udp_feature_separation.parquet"
    write_parquet_with_fallback(concrete, concrete_path, index=False)

    spread_cols = [
        "feature", "feature_family", "abs_log_std_ratio",
        "std_ratio_udp_over_tcp", "variance_ratio_udp_over_tcp",
        "higher_spread_class", "auc_separation", "cohens_d_udp_minus_tcp",
        "tcp_std", "udp_std", "tcp_mean", "udp_mean",
    ]
    spread = (
        concrete[np.isfinite(concrete["abs_log_std_ratio"])]
        .sort_values(["abs_log_std_ratio", "feature"], ascending=[False, True])
        [spread_cols]
    )
    spread_path = results_dir / "tcp_udp_feature_spread_separation.csv"
    write_csv_with_fallback(spread.head(50), spread_path, index=False)

    family_rows = []
    for family, group in concrete.groupby("feature_family"):
        ranked = group.sort_values(
            ["auc_separation", "feature"], ascending=[False, True]
        )
        rep = ranked.iloc[0]
        spread_group = group[np.isfinite(group["abs_log_std_ratio"])]
        spread_rep = (
            spread_group.sort_values(
                ["abs_log_std_ratio", "feature"], ascending=[False, True]
            ).iloc[0]
            if len(spread_group) else rep
        )
        family_rows.append({
            "feature_family": family,
            "representative_feature": rep["feature"],
            "representative_auc_separation": rep["auc_separation"],
            "representative_auc_udp_vs_tcp": rep["auc_udp_vs_tcp"],
            "higher_value_class": rep["higher_value_class"],
            "mean_diff_udp_minus_tcp": rep["mean_diff_udp_minus_tcp"],
            "tcp_mean": rep["tcp_mean"],
            "udp_mean": rep["udp_mean"],
            "tcp_std": rep["tcp_std"],
            "udp_std": rep["udp_std"],
            "std_ratio_udp_over_tcp": rep["std_ratio_udp_over_tcp"],
            "variance_ratio_udp_over_tcp": rep["variance_ratio_udp_over_tcp"],
            "cohens_d_udp_minus_tcp": rep["cohens_d_udp_minus_tcp"],
            "family_mean_auc_separation": group["auc_separation"].mean(),
            "family_max_auc_separation": group["auc_separation"].max(),
            "spread_representative_feature": spread_rep["feature"],
            "spread_abs_log_std_ratio": spread_rep["abs_log_std_ratio"],
            "spread_std_ratio_udp_over_tcp": spread_rep["std_ratio_udp_over_tcp"],
            "spread_higher_class": spread_rep["higher_spread_class"],
            "spread_feature_auc_separation": spread_rep["auc_separation"],
            "n_concrete_features": int(len(group)),
            "n_tcp": int(rep["n_tcp"]),
            "n_udp": int(rep["n_udp"]),
        })

    families = pd.DataFrame(family_rows).sort_values(
        ["representative_auc_separation", "feature_family"],
        ascending=[False, True],
    )
    family_path = results_dir / "tcp_udp_family_separation.csv"
    write_csv_with_fallback(families, family_path, index=False)
    logger.info("Saved tcp/udp feature separation -> %s", family_path)
    return concrete, families


def binary_entropy(probs: np.ndarray) -> np.ndarray:
    clipped = np.clip(probs, EPS, 1.0 - EPS)
    return -(clipped * np.log(clipped) + (1.0 - clipped) * np.log(1.0 - clipped))


def _tcp_udp_test_context(
    df: pd.DataFrame,
    X: pd.DataFrame,
    calibrated: Any,
    label_encoder: Any,
    models_dir: Path,
    test_idx: np.ndarray,
) -> dict[str, Any]:
    test_df = df.iloc[test_idx].reset_index(drop=True)
    X_test = X.iloc[test_idx].reset_index(drop=True)
    probs = calibrated.predict_proba(X_test)
    preds = probs.argmax(axis=1)
    y_true = label_encoder.transform(test_df["label_type"].to_numpy())
    class_names = label_encoder.classes_
    tcp_idx = int(np.where(class_names == "gafgyt_tcp")[0][0])
    udp_idx = int(np.where(class_names == "gafgyt_udp")[0][0])
    order = np.argsort(-probs, axis=1)
    p_top1 = probs[np.arange(len(probs)), order[:, 0]]
    p_top2 = probs[np.arange(len(probs)), order[:, 1]]
    stage_a_flags = run_stage_a_on_test(test_df, models_dir)
    return {
        "test_df": test_df,
        "probs": probs,
        "preds": preds,
        "y_true": y_true,
        "tcp_idx": tcp_idx,
        "udp_idx": udp_idx,
        "margin": p_top1 - p_top2,
        "stage_a_flags": stage_a_flags,
    }


def export_tcp_udp_entropy_brier_sanity(
    df: pd.DataFrame,
    X: pd.DataFrame,
    calibrated: Any,
    label_encoder: Any,
    models_dir: Path,
    test_idx: np.ndarray,
    results_dir: Path,
) -> dict[str, float]:
    ctx = _tcp_udp_test_context(
        df, X, calibrated, label_encoder, models_dir, test_idx
    )
    test_df = ctx["test_df"]
    probs = ctx["probs"]
    y_true = ctx["y_true"]
    tcp_idx = ctx["tcp_idx"]
    udp_idx = ctx["udp_idx"]

    weak_mask = (
        test_df["device_name"].isin(WEAK_DEVICES).to_numpy()
        & test_df["label_type"].isin(WEAK_CLASSES).to_numpy()
    )
    p_tcp = probs[weak_mask, tcp_idx]
    p_udp = probs[weak_mask, udp_idx]
    y_tcp = (y_true[weak_mask] == tcp_idx).astype(int)
    y_udp = (y_true[weak_mask] == udp_idx).astype(int)

    full_entropy = entropy_nats(probs[weak_mask])
    tcp_binary_entropy = binary_entropy(p_tcp)
    sanity = {
        "n_weak_test": int(weak_mask.sum()),
        "brier_tcp": float(np.mean((y_tcp - p_tcp) ** 2)),
        "brier_udp": float(np.mean((y_udp - p_udp) ** 2)),
        "brier_abs_diff": float(abs(
            np.mean((y_tcp - p_tcp) ** 2) - np.mean((y_udp - p_udp) ** 2)
        )),
        "max_abs_p_tcp_plus_p_udp_minus_1": float(
            np.max(np.abs((p_tcp + p_udp) - 1.0))
        ),
        "mean_abs_p_tcp_plus_p_udp_minus_1": float(
            np.mean(np.abs((p_tcp + p_udp) - 1.0))
        ),
        "max_abs_entropy_minus_binary_entropy_p_tcp": float(
            np.max(np.abs(full_entropy - tcp_binary_entropy))
        ),
        "mean_abs_entropy_minus_binary_entropy_p_tcp": float(
            np.mean(np.abs(full_entropy - tcp_binary_entropy))
        ),
        "entropy_mean": float(full_entropy.mean()),
        "binary_entropy_p_tcp_mean": float(tcp_binary_entropy.mean()),
    }
    out_path = results_dir / "tcp_udp_weak_entropy_brier_sanity.json"
    write_text_with_fallback(
        out_path, json.dumps(sanity, indent=2), encoding="utf-8"
    )
    logger.info("Saved tcp/udp entropy+Brier sanity -> %s", out_path)
    return sanity


def export_tcp_udp_hedging_threshold_tradeoff(
    alerts: pd.DataFrame,
    df: pd.DataFrame,
    X: pd.DataFrame,
    calibrated: Any,
    label_encoder: Any,
    models_dir: Path,
    test_idx: np.ndarray,
    results_dir: Path,
    thresholds: tuple[float, ...] = (0.5, 0.9, 0.95, 0.99),
) -> tuple[pd.DataFrame, pd.DataFrame]:
    ctx = _tcp_udp_test_context(
        df, X, calibrated, label_encoder, models_dir, test_idx
    )
    test_df = ctx["test_df"]
    preds = ctx["preds"]
    y_true = ctx["y_true"]
    tcp_idx = ctx["tcp_idx"]
    udp_idx = ctx["udp_idx"]
    margin = ctx["margin"]
    stage_a_flags = ctx["stage_a_flags"]

    true_tcp_udp_gated = (
        ((y_true == tcp_idx) | (y_true == udp_idx)) & stage_a_flags
    )
    tcp_to_udp_error = (y_true == tcp_idx) & (preds == udp_idx) & stage_a_flags
    n_errors = int(tcp_to_udp_error.sum())

    rows = []
    for threshold in thresholds:
        hedged_alerts = alerts["margin"].to_numpy() <= threshold
        hedged_test = margin <= threshold
        caught = tcp_to_udp_error & hedged_test
        hedged_tcp_udp = true_tcp_udp_gated & hedged_test
        rows.append({
            "margin_threshold": threshold,
            "hedged_alerts_n": int(hedged_alerts.sum()),
            "hedged_alerts_frac": float(hedged_alerts.mean()),
            "tcp_to_udp_errors_total": n_errors,
            "tcp_to_udp_errors_caught": int(caught.sum()),
            "tcp_to_udp_error_capture_rate": float(caught.sum() / n_errors)
            if n_errors else np.nan,
            "hedged_gated_true_tcp_udp_n": int(hedged_tcp_udp.sum()),
            "hedged_gated_true_tcp_udp_error_rate": float(
                caught.sum() / hedged_tcp_udp.sum()
            ) if hedged_tcp_udp.sum() else np.nan,
            "hedged_all_alert_error_rate": float(caught.sum() / hedged_alerts.sum())
            if hedged_alerts.sum() else np.nan,
        })

    threshold_df = pd.DataFrame(rows)
    threshold_path = results_dir / "tcp_udp_hedging_threshold_tradeoff.csv"
    write_csv_with_fallback(threshold_df, threshold_path, index=False)

    band = _margin_bands(pd.Series(margin))
    band_df = pd.DataFrame({
        "margin_bin": band.astype(str),
        "is_gated_true_tcp_udp": true_tcp_udp_gated,
        "is_tcp_to_udp_error": tcp_to_udp_error,
    })
    band_summary = (
        band_df.groupby("margin_bin")
               .agg(
                   gated_true_tcp_udp_n=("is_gated_true_tcp_udp", "sum"),
                   tcp_to_udp_errors=("is_tcp_to_udp_error", "sum"),
               )
               .reset_index()
    )
    band_summary["tcp_to_udp_error_rate"] = (
        band_summary["tcp_to_udp_errors"]
        / band_summary["gated_true_tcp_udp_n"].replace(0, np.nan)
    )
    band_path = results_dir / "tcp_udp_margin_band_error_rates.csv"
    write_csv_with_fallback(band_summary, band_path, index=False)
    logger.info("Saved tcp/udp hedging threshold tradeoff -> %s", threshold_path)
    return threshold_df, band_summary


def export_tcp_udp_hh_jit_overlap_reference(
    df: pd.DataFrame,
    train_idx: np.ndarray,
    test_idx: np.ndarray,
    results_dir: Path,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    features = [
        c for c in traffic_feature_cols_from_df(df)
        if feature_family(c) == "HH_jit_mean"
    ]
    train_df = df.iloc[train_idx]
    stats_rows = []
    for feature in features:
        tcp_values = train_df.loc[
            train_df["label_type"] == "gafgyt_tcp", feature
        ].to_numpy(dtype=float)
        udp_values = train_df.loc[
            train_df["label_type"] == "gafgyt_udp", feature
        ].to_numpy(dtype=float)
        tcp_p10, tcp_p90 = np.quantile(tcp_values, [0.10, 0.90])
        udp_p10, udp_p90 = np.quantile(udp_values, [0.10, 0.90])
        overlap_low = max(tcp_p10, udp_p10)
        overlap_high = min(tcp_p90, udp_p90)
        has_overlap = overlap_low <= overlap_high
        if has_overlap:
            boundary_low = overlap_low
            boundary_high = overlap_high
            boundary_type = "p10_p90_overlap"
        else:
            boundary_low = min(tcp_p10, udp_p10, tcp_p90, udp_p90)
            boundary_high = max(
                min(tcp_p10, tcp_p90),
                min(udp_p10, udp_p90),
            )
            if udp_p90 < tcp_p10:
                boundary_low = udp_p90
                boundary_high = tcp_p10
            elif tcp_p90 < udp_p10:
                boundary_low = tcp_p90
                boundary_high = udp_p10
            boundary_type = "p10_p90_gap"
        stats_rows.append({
            "feature": feature,
            "tcp_median": float(np.median(tcp_values)),
            "tcp_p10": float(tcp_p10),
            "tcp_p90": float(tcp_p90),
            "udp_median": float(np.median(udp_values)),
            "udp_p10": float(udp_p10),
            "udp_p90": float(udp_p90),
            "overlap_low_p10_p90": float(overlap_low),
            "overlap_high_p10_p90": float(overlap_high),
            "has_p10_p90_overlap": bool(has_overlap),
            "boundary_type": boundary_type,
            "boundary_low": float(boundary_low),
            "boundary_high": float(boundary_high),
            "n_tcp_train": int(len(tcp_values)),
            "n_udp_train": int(len(udp_values)),
        })

    stats = pd.DataFrame(stats_rows)
    stats_path = results_dir / "tcp_udp_hh_jit_overlap_reference.csv"
    write_csv_with_fallback(stats, stats_path, index=False)

    detail_path = results_dir / "tcp_udp_gated_misclassifications.parquet"
    if detail_path.exists():
        errors = pd.read_parquet(detail_path)
    else:
        errors = pd.DataFrame(columns=["sample_id"])
    test_df = df.iloc[test_idx].reset_index(drop=True)
    error_rows = []
    for feature in features:
        values = test_df.loc[
            test_df["sample_id"].isin(errors["sample_id"]), feature
        ].to_numpy(dtype=float)
        if len(values):
            ref_row = stats[stats["feature"] == feature].iloc[0]
            in_boundary = (
                (values >= ref_row["boundary_low"])
                & (values <= ref_row["boundary_high"])
            )
            error_rows.append({
                "feature": feature,
                "n_tcp_to_udp_errors": int(len(values)),
                "error_median": float(np.median(values)),
                "error_p10": float(np.quantile(values, 0.10)),
                "error_p90": float(np.quantile(values, 0.90)),
                "error_min": float(np.min(values)),
                "error_max": float(np.max(values)),
                "boundary_type": ref_row["boundary_type"],
                "boundary_low": float(ref_row["boundary_low"]),
                "boundary_high": float(ref_row["boundary_high"]),
                "error_frac_in_boundary": float(in_boundary.mean()),
            })
    error_stats = pd.DataFrame(error_rows)
    error_path = results_dir / "tcp_udp_hh_jit_misclassification_stats.csv"
    write_csv_with_fallback(error_stats, error_path, index=False)

    plot_feature = "HH_jit_L0.01_mean"
    if plot_feature in features and len(errors):
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        tcp_values = train_df.loc[
            train_df["label_type"] == "gafgyt_tcp", plot_feature
        ].to_numpy(dtype=float)
        udp_values = train_df.loc[
            train_df["label_type"] == "gafgyt_udp", plot_feature
        ].to_numpy(dtype=float)
        error_values = test_df.loc[
            test_df["sample_id"].isin(errors["sample_id"]), plot_feature
        ].to_numpy(dtype=float)

        fig, ax = plt.subplots(figsize=(7.0, 4.2))
        ax.hist(tcp_values, bins=60, density=True, alpha=0.45, label="gafgyt_tcp")
        ax.hist(udp_values, bins=60, density=True, alpha=0.45, label="gafgyt_udp")
        ax.scatter(
            error_values,
            np.zeros_like(error_values),
            marker="|",
            s=80,
            color="#111827",
            label="tcp->udp errors",
            zorder=3,
        )
        row = stats[stats["feature"] == plot_feature].iloc[0]
        ax.axvspan(
            row["boundary_low"],
            row["boundary_high"],
            color="#f59e0b",
            alpha=0.18,
            label=row["boundary_type"],
        )
        ax.set_title("tcp/udp HH_jit_L0.01_mean reference")
        ax.set_xlabel(plot_feature)
        ax.set_ylabel("Density")
        ax.legend()
        fig.tight_layout()
        plot_path = results_dir / "tcp_udp_hh_jit_L0.01_mean_overlap.png"
        savefig_with_fallback(fig, plot_path, dpi=160)
        plt.close(fig)

    logger.info("Saved tcp/udp HH_jit overlap reference -> %s", stats_path)
    return stats, error_stats


def _sample_for_shap(
    df: pd.DataFrame,
    max_rows: int,
    random_state: int,
) -> pd.DataFrame:
    if max_rows <= 0 or len(df) <= max_rows:
        return df

    per_class = max(1, max_rows // df["label_type"].nunique())
    sampled = (
        df.groupby("label_type", group_keys=False)
          .apply(lambda g: g.sample(min(len(g), per_class), random_state=random_state))
    )
    if len(sampled) < max_rows:
        remaining = df.drop(index=sampled.index)
        extra_n = min(max_rows - len(sampled), len(remaining))
        if extra_n > 0:
            sampled = pd.concat([
                sampled,
                remaining.sample(extra_n, random_state=random_state),
            ])
    return sampled.sort_index()


def _shap_values_for_classes(raw_model: Any, X: pd.DataFrame) -> np.ndarray:
    try:
        import shap
    except ImportError as exc:
        raise ImportError(
            "SHAP exports require the 'shap' package. Install it before running "
            "module1_exports.py with SHAP enabled."
        ) from exc

    explainer = shap.TreeExplainer(raw_model)
    values = explainer.shap_values(X)
    if isinstance(values, list):
        return np.stack(values, axis=2)

    arr = np.asarray(values)
    if arr.ndim == 3:
        if arr.shape[1] == X.shape[1]:
            return arr
        if arr.shape[2] == X.shape[1]:
            return np.transpose(arr, (0, 2, 1))
    if arr.ndim == 2:
        return arr[:, :, np.newaxis]
    raise ValueError(f"Unsupported SHAP value shape: {arr.shape}")


def _aggregate_local_families(
    values: np.ndarray,
    family_to_indices: dict[str, list[int]],
) -> dict[str, float]:
    return {
        family: float(values[indices].sum())
        for family, indices in family_to_indices.items()
    }


def export_shap_atypicality(
    shap_values: np.ndarray,
    y_pred: np.ndarray,
    profiles: pd.DataFrame,
    class_names: np.ndarray,
    family_to_indices: dict[str, list[int]],
    sample_ids: np.ndarray,
    results_dir: Path,
    top_k: int,
) -> pd.DataFrame:
    profile_top = {
        class_name: set(
            profiles[profiles["class"] == class_name]
            .nlargest(top_k, "mean_abs_shap")["feature_family"]
        )
        for class_name in class_names
    }

    rows = []
    for row_idx, pred_idx in enumerate(y_pred):
        class_name = class_names[pred_idx]
        local_family_values = _aggregate_local_families(
            shap_values[row_idx, :, pred_idx],
            family_to_indices,
        )
        local_top = {
            family for family, _ in sorted(
                local_family_values.items(),
                key=lambda kv: abs(kv[1]),
                reverse=True,
            )[:top_k]
        }
        global_top = profile_top[class_name]
        overlap = len(local_top & global_top) / top_k if top_k else np.nan
        rows.append({
            "sample_id": sample_ids[row_idx],
            "pred_class": class_name,
            "global_overlap": float(overlap),
            "atypicality_score": float(1.0 - overlap),
        })

    atypicality = pd.DataFrame(rows)
    atypicality_path = results_dir / "shap_atypicality_sample.parquet"
    write_parquet_with_fallback(atypicality, atypicality_path, index=False)

    summary = (
        atypicality.groupby("pred_class")
                   .agg(
                       n=("sample_id", "size"),
                       mean_atypicality=("atypicality_score", "mean"),
                       p50_atypicality=("atypicality_score", "median"),
                       p90_atypicality=(
                           "atypicality_score",
                           lambda s: s.quantile(0.90),
                       ),
                       p95_atypicality=(
                           "atypicality_score",
                           lambda s: s.quantile(0.95),
                       ),
                   )
                   .reset_index()
    )
    summary_path = results_dir / "shap_atypicality_summary.csv"
    write_csv_with_fallback(summary, summary_path, index=False)
    logger.info("Saved SHAP atypicality summary -> %s", summary_path)
    return summary


def export_shap_global_profiles(
    df: pd.DataFrame,
    X: pd.DataFrame,
    calibrated: Any,
    raw_model: Any,
    label_encoder: Any,
    results_dir: Path,
    max_rows: int,
    random_state: int,
    top_k: int,
) -> pd.DataFrame:
    sample_df = _sample_for_shap(df, max_rows=max_rows, random_state=random_state)
    X_sample = X.loc[sample_df.index]
    shap_values = _shap_values_for_classes(raw_model, X_sample)
    y_pred = calibrated.predict_proba(X_sample).argmax(axis=1)

    feature_cols = list(X_sample.columns)
    non_device_idx = [
        i for i, col in enumerate(feature_cols)
        if not col.startswith("dev_") and is_explainable_feature(col)
    ]
    family_to_indices: dict[str, list[int]] = {}
    for idx in non_device_idx:
        family_to_indices.setdefault(feature_family(feature_cols[idx]), []).append(idx)

    rows = []
    class_names = label_encoder.classes_
    for class_idx, class_name in enumerate(class_names):
        mask = y_pred == class_idx
        n_class = int(mask.sum())
        if n_class == 0:
            logger.warning("No SHAP sample rows predicted as %s", class_name)
            continue
        class_values = shap_values[mask, :, class_idx]
        for family, indices in family_to_indices.items():
            family_values = class_values[:, indices].sum(axis=1)
            concrete_mean_abs = np.abs(class_values[:, indices]).mean(axis=0)
            rep_local_idx = int(np.argmax(concrete_mean_abs))
            rep_feature_idx = indices[rep_local_idx]
            rows.append({
                "class": class_name,
                "feature_family": family,
                "mean_abs_shap": float(np.abs(family_values).mean()),
                "mean_signed_shap": float(family_values.mean()),
                "representative_feature": feature_cols[rep_feature_idx],
                "representative_feature_mean_abs_shap": float(
                    concrete_mean_abs[rep_local_idx]
                ),
                "n_samples": n_class,
            })

    profiles = pd.DataFrame(rows).sort_values(
        ["class", "mean_abs_shap"], ascending=[True, False]
    )
    out_path = results_dir / "shap_global_profiles.parquet"
    write_parquet_with_fallback(profiles, out_path, index=False)
    logger.info("Saved SHAP global profiles -> %s", out_path)

    top_signed = (
        profiles.groupby("class", group_keys=False)
                .head(top_k)
                .assign(signed_positive=lambda d: d["mean_signed_shap"] > 0)
                .groupby("class")
                .agg(
                    n_top=("feature_family", "size"),
                    n_signed_positive=("signed_positive", "sum"),
                    frac_signed_positive=("signed_positive", "mean"),
                    min_top_signed_shap=("mean_signed_shap", "min"),
                    max_top_signed_shap=("mean_signed_shap", "max"),
                )
                .reset_index()
    )
    top_signed_path = results_dir / "shap_global_top_signed_sanity.csv"
    write_csv_with_fallback(top_signed, top_signed_path, index=False)
    logger.info("Saved SHAP signed sanity check -> %s", top_signed_path)

    export_shap_atypicality(
        shap_values=shap_values,
        y_pred=y_pred,
        profiles=profiles,
        class_names=class_names,
        family_to_indices=family_to_indices,
        sample_ids=sample_df["sample_id"].to_numpy()
        if "sample_id" in sample_df.columns else sample_df.index.to_numpy(),
        results_dir=results_dir,
        top_k=top_k,
    )
    return profiles


def export_tcp_udp_polarity_shap(
    df: pd.DataFrame,
    X: pd.DataFrame,
    calibrated: Any,
    raw_model: Any,
    label_encoder: Any,
    results_dir: Path,
    chunk_size: int,
    max_rows: int | None = None,
) -> pd.DataFrame:
    """Diagnose the model's tcp-versus-udp polarity on its own pair predictions.

    For every sample whose calibrated prediction is gafgyt_tcp or gafgyt_udp,
    this computes SHAP(tcp) - SHAP(udp). Traffic windows are collapsed to their
    feature family, while each device dummy remains separate so device priors
    can be compared directly with traffic evidence.
    """
    tcp_idx, udp_idx = tcp_udp_class_indices(label_encoder)
    predicted = calibrated.predict_proba(X).argmax(axis=1)
    pair_population = np.flatnonzero(np.isin(predicted, [tcp_idx, udp_idx]))
    if len(pair_population) == 0:
        raise RuntimeError("No samples were predicted as gafgyt_tcp or gafgyt_udp.")
    pair_positions = pair_population
    if max_rows is not None and 0 < max_rows < len(pair_population):
        candidate = pd.DataFrame({
            "position": pair_population,
            "device_name": df.iloc[pair_population]["device_name"].to_numpy(),
        })
        device_groups = list(candidate.groupby("device_name", sort=True))
        per_device = max_rows // len(device_groups)
        remainder = max_rows % len(device_groups)
        sampled = []
        for group_idx, (_, group) in enumerate(device_groups):
            n_take = min(len(group), per_device + (group_idx < remainder))
            sampled.append(group.sample(n=n_take, random_state=RANDOM_STATE))
        pair_positions = np.sort(pd.concat(sampled)["position"].to_numpy())

    feature_cols = list(X.columns)
    unit_to_indices: dict[str, list[int]] = {}
    unit_kind: dict[str, str] = {}
    for idx, feature in enumerate(feature_cols):
        if feature.startswith("dev_"):
            unit_to_indices[feature] = [idx]
            unit_kind[feature] = "device_one_hot"
        else:
            family = feature_family(feature)
            unit_to_indices.setdefault(family, []).append(idx)
            unit_kind[family] = "traffic_feature_family"

    unit_names = list(unit_to_indices)
    aggregation = np.zeros((len(feature_cols), len(unit_names)), dtype=float)
    for unit_idx, unit in enumerate(unit_names):
        aggregation[unit_to_indices[unit], unit_idx] = 1.0

    totals: dict[tuple[str, str], dict[str, Any]] = {}

    def update(scope_type: str, scope_value: str, values: np.ndarray) -> None:
        key = (scope_type, scope_value)
        stats = totals.setdefault(key, {
            "n_samples": 0,
            "sum": np.zeros(len(unit_names), dtype=float),
            "sum_abs": np.zeros(len(unit_names), dtype=float),
        })
        stats["n_samples"] += len(values)
        stats["sum"] += values.sum(axis=0)
        stats["sum_abs"] += np.abs(values).sum(axis=0)

    for start in range(0, len(pair_positions), chunk_size):
        positions = pair_positions[start:start + chunk_size]
        shap_values = _shap_values_for_classes(raw_model, X.iloc[positions])
        delta = shap_values[:, :, tcp_idx] - shap_values[:, :, udp_idx]
        units = delta @ aggregation
        update("overall", "gafgyt_tcp_or_udp", units)

        chunk_predictions = predicted[positions]
        for class_idx in (tcp_idx, udp_idx):
            mask = chunk_predictions == class_idx
            if mask.any():
                update("predicted_class", str(label_encoder.classes_[class_idx]), units[mask])

        chunk_devices = df.iloc[positions]["device_name"].to_numpy()
        for device_name in np.unique(chunk_devices):
            mask = chunk_devices == device_name
            update("device_name", str(device_name), units[mask])

        logger.info(
            "tcp/udp polarity SHAP: %d/%d predicted-pair rows",
            min(start + len(positions), len(pair_positions)),
            len(pair_positions),
        )

    rows = []
    for (scope_type, scope_value), stats in totals.items():
        n_samples = int(stats["n_samples"])
        mean_signed = stats["sum"] / n_samples
        mean_abs = stats["sum_abs"] / n_samples
        for unit_idx, unit in enumerate(unit_names):
            rows.append({
                "scope_type": scope_type,
                "scope_value": scope_value,
                "n_samples": n_samples,
                "feature_unit": unit,
                "unit_kind": unit_kind[unit],
                "mean_abs_shap_tcp_minus_udp": float(mean_abs[unit_idx]),
                "mean_signed_shap_tcp_minus_udp": float(mean_signed[unit_idx]),
            })

    polarity = pd.DataFrame(rows)
    polarity["rank_by_abs_within_scope"] = (
        polarity.groupby(["scope_type", "scope_value"])[
            "mean_abs_shap_tcp_minus_udp"
        ].rank(method="first", ascending=False).astype(int)
    )
    polarity = polarity.sort_values(
        ["scope_type", "scope_value", "rank_by_abs_within_scope"]
    )
    write_csv_with_fallback(
        polarity,
        results_dir / "tcp_udp_predicted_polarity_shap.csv",
        index=False,
    )

    device_counts = pd.DataFrame({
        "device_name": df.iloc[pair_positions]["device_name"].to_numpy(),
        "predicted_class": label_encoder.classes_[predicted[pair_positions]],
    }).groupby("device_name").agg(
        n_shap_sampled_predicted_tcp_or_udp=("predicted_class", "size"),
        n_shap_sampled_predicted_tcp=(
            "predicted_class", lambda s: int((s == "gafgyt_tcp").sum())
        ),
        n_shap_sampled_predicted_udp=(
            "predicted_class", lambda s: int((s == "gafgyt_udp").sum())
        ),
    ).reset_index()
    own_dummy = polarity[polarity["scope_type"] == "device_name"].copy()
    own_dummy["device_name"] = own_dummy["scope_value"]
    own_dummy = own_dummy[
        own_dummy["feature_unit"] == "dev_" + own_dummy["device_name"]
    ][[
        "device_name",
        "mean_abs_shap_tcp_minus_udp",
        "mean_signed_shap_tcp_minus_udp",
        "rank_by_abs_within_scope",
    ]]
    device_polarity = device_counts.merge(own_dummy, on="device_name", how="left")
    device_polarity["predicted_tcp_fraction"] = (
        device_polarity["n_shap_sampled_predicted_tcp"]
        / device_polarity["n_shap_sampled_predicted_tcp_or_udp"]
    )
    write_csv_with_fallback(
        device_polarity.sort_values("device_name"),
        results_dir / "tcp_udp_predicted_polarity_by_device.csv",
        index=False,
    )

    overall = polarity[
        (polarity["scope_type"] == "overall")
        & (polarity["scope_value"] == "gafgyt_tcp_or_udp")
    ]
    summary = {
        "definition": "SHAP(gafgyt_tcp) - SHAP(gafgyt_udp) on calibrated tcp/udp predictions",
        "n_predicted_tcp_or_udp_population": int(len(pair_population)),
        "n_shap_sampled_tcp_or_udp": int(len(pair_positions)),
        "top_units_overall": overall.head(15)[[
            "feature_unit",
            "unit_kind",
            "mean_abs_shap_tcp_minus_udp",
            "mean_signed_shap_tcp_minus_udp",
        ]].to_dict(orient="records"),
        "top_device_one_hot_units": overall[
            overall["unit_kind"] == "device_one_hot"
        ].head(9)[[
            "feature_unit",
            "mean_abs_shap_tcp_minus_udp",
            "mean_signed_shap_tcp_minus_udp",
        ]].to_dict(orient="records"),
        "top_traffic_family_units": overall[
            overall["unit_kind"] == "traffic_feature_family"
        ].head(10)[[
            "feature_unit",
            "mean_abs_shap_tcp_minus_udp",
            "mean_signed_shap_tcp_minus_udp",
        ]].to_dict(orient="records"),
        "per_device_own_dummy": device_polarity.sort_values(
            "device_name"
        ).to_dict(orient="records"),
    }
    write_text_with_fallback(
        results_dir / "tcp_udp_predicted_polarity_shap_summary.json",
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )
    logger.info("Saved tcp/udp predicted-pair polarity SHAP -> %s", results_dir)
    return polarity


@dataclass
class Module1Explainer:
    calibrated: Any
    raw_model: Any
    label_encoder: Any
    feature_cols: list[str]
    shap_global_profiles: pd.DataFrame
    benign_reference_stats: pd.DataFrame

    @classmethod
    def from_artifacts(
        cls,
        models_dir: str | Path | None = None,
        results_dir: str | Path | None = None,
    ) -> "Module1Explainer":
        script_dir = Path(__file__).resolve().parent
        models_dir = Path(models_dir) if models_dir is not None else script_dir / "models"
        results_dir = (
            Path(results_dir) if results_dir is not None else script_dir / "results"
        )
        artifacts = load_artifacts(models_dir)
        return cls(
            calibrated=artifacts["calibrated"],
            raw_model=artifacts["raw_model"],
            label_encoder=artifacts["label_encoder"],
            feature_cols=artifacts["feature_cols"],
            shap_global_profiles=pd.read_parquet(
                results_dir / "shap_global_profiles.parquet"
            ),
            benign_reference_stats=pd.read_parquet(
                results_dir / "benign_reference_stats.parquet"
            ),
        )

    def explain_alert(
        self,
        x: pd.Series | dict[str, Any] | pd.DataFrame,
        pred_class: str,
        top_k: int = 5,
    ) -> dict[str, Any]:
        if isinstance(x, pd.DataFrame):
            if len(x) != 1:
                raise ValueError("explain_alert expects exactly one row.")
            row_df = x.copy()
        else:
            row_df = pd.DataFrame([dict(x)])

        if "sample_id" not in row_df.columns:
            row_df["sample_id"] = row_df.index

        X_row = prepare_stage_b_features(row_df, self.feature_cols)
        shap_values = _shap_values_for_classes(self.raw_model, X_row)
        class_idx = int(np.where(self.label_encoder.classes_ == pred_class)[0][0])
        local_values = shap_values[0, :, class_idx]

        feature_rows = []
        for i, col in enumerate(self.feature_cols):
            if col.startswith("dev_") or not is_explainable_feature(col):
                continue
            feature_rows.append({
                "feature": col,
                "feature_family": feature_family(col),
                "shap": float(local_values[i]),
                "abs_shap": float(abs(local_values[i])),
            })
        local_df = pd.DataFrame(feature_rows)

        family_df = (
            local_df.groupby("feature_family", as_index=False)
                    .agg(family_shap=("shap", "sum"))
        )
        family_df["abs_family_shap"] = family_df["family_shap"].abs()
        top_families = family_df.nlargest(top_k, "abs_family_shap")

        device_name = str(row_df["device_name"].iloc[0])
        evidence_rows = []
        for _, fam_row in top_families.iterrows():
            family = fam_row["feature_family"]
            family_features = local_df[local_df["feature_family"] == family]
            rep = family_features.nlargest(1, "abs_shap").iloc[0]
            feature = rep["feature"]
            actual = float(row_df[feature].iloc[0])
            ref = self._lookup_reference(device_name, feature, actual)
            evidence_rows.append({
                "feature_family": family,
                "family_shap": float(fam_row["family_shap"]),
                "direction": "supports_pred_class"
                if fam_row["family_shap"] >= 0 else "argues_against_pred_class",
                "representative_feature": feature,
                "representative_feature_shap": float(rep["shap"]),
                "actual_value": actual,
                "benign_reference": ref,
            })

        local_family_set = set(top_families["feature_family"])
        global_top = (
            self.shap_global_profiles[
                self.shap_global_profiles["class"] == pred_class
            ]
            .nlargest(top_k, "mean_abs_shap")
        )
        global_family_set = set(global_top["feature_family"])
        overlap = (
            len(local_family_set & global_family_set) / top_k
            if top_k else np.nan
        )

        probs = self.calibrated.predict_proba(X_row)[0]
        top_order = np.argsort(-probs)
        return {
            "sample_id": row_df["sample_id"].iloc[0],
            "device_name": device_name,
            "pred_class": pred_class,
            "p_vector": probs.astype(float).tolist(),
            "p_top1": float(probs[top_order[0]]),
            "top2_class": str(self.label_encoder.classes_[top_order[1]]),
            "p_top2": float(probs[top_order[1]]),
            "margin": float(probs[top_order[0]] - probs[top_order[1]]),
            "entropy": float(entropy_nats(probs.reshape(1, -1))[0]),
            "top_feature_families": evidence_rows,
            "global_profile_top_families": global_top[
                ["feature_family", "mean_abs_shap", "mean_signed_shap"]
            ].to_dict(orient="records"),
            "global_overlap": float(overlap),
            "atypicality_score": float(1.0 - overlap),
        }

    def _lookup_reference(
        self,
        device_name: str,
        feature: str,
        actual: float,
    ) -> dict[str, float]:
        try:
            stats = self.benign_reference_stats.loc[device_name, feature]
        except KeyError:
            return {
                "median": np.nan,
                "std": np.nan,
                "p99": np.nan,
                "value_to_median_ratio": np.nan,
                "value_to_p99_ratio": np.nan,
                "z_score_vs_benign": np.nan,
            }

        median = float(stats["median"])
        std = float(stats["std"])
        p99 = float(stats["p99"])
        return {
            "median": median,
            "std": std,
            "p99": p99,
            "value_to_median_ratio": float(actual / median)
            if abs(median) > EPS else np.nan,
            "value_to_p99_ratio": float(actual / p99)
            if abs(p99) > EPS else np.nan,
            "z_score_vs_benign": float((actual - median) / std)
            if abs(std) > EPS else np.nan,
        }


_DEFAULT_EXPLAINER: Module1Explainer | None = None


def explain_alert(
    x: pd.Series | dict[str, Any] | pd.DataFrame,
    pred_class: str,
    top_k: int = 5,
    explainer: Module1Explainer | None = None,
) -> dict[str, Any]:
    """
    Return the Module 2 evidence block for one alert.

    Pass an explicit Module1Explainer in batch jobs to avoid reloading artefacts.
    """
    global _DEFAULT_EXPLAINER
    if explainer is None:
        if _DEFAULT_EXPLAINER is None:
            _DEFAULT_EXPLAINER = Module1Explainer.from_artifacts()
        explainer = _DEFAULT_EXPLAINER
    return explainer.explain_alert(x, pred_class, top_k=top_k)


def traffic_feature_cols_from_df(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if c not in META_COLS and not c.startswith("dev_")]


def explainable_traffic_feature_cols_from_df(df: pd.DataFrame) -> list[str]:
    return [c for c in traffic_feature_cols_from_df(df) if is_explainable_feature(c)]


def run_exports(args: argparse.Namespace) -> None:
    data_path = Path(args.data_path)
    models_dir = Path(args.models_dir)
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading sampled data from %s", data_path)
    df = pd.read_parquet(data_path)
    if "sample_id" not in df.columns:
        df = df.copy()
        df["sample_id"] = df.index

    export_feature_leakage_audit(df, results_dir)

    artifacts = load_artifacts(models_dir)
    X = prepare_stage_b_features(df, artifacts["feature_cols"])
    probs = artifacts["calibrated"].predict_proba(X)
    export_schema_metadata(artifacts["label_encoder"], results_dir)

    alerts = export_alerts_full(
        df=df,
        X=X,
        calibrated=artifacts["calibrated"],
        raw_model=artifacts["raw_model"],
        label_encoder=artifacts["label_encoder"],
        models_dir=models_dir,
        results_dir=results_dir,
    )
    export_margin_band_summary(alerts, results_dir)

    split_indices = reconstruct_stage_b_split_indices(df, artifacts["label_encoder"])
    split_check = verify_reconstructed_test_split(
        df=df,
        X=X,
        calibrated=artifacts["calibrated"],
        label_encoder=artifacts["label_encoder"],
        test_idx=split_indices["test"],
        results_dir=results_dir,
    )
    if args.calibration_split == "test":
        if not split_check.get("matches_saved_report", False):
            raise RuntimeError(
                "Reconstructed test split did not match saved Stage B metrics; "
                "refusing to export test-only calibration."
            )
        cal_idx = split_indices["test"]
        cal_df = df.iloc[cal_idx].reset_index(drop=True)
        cal_probs = probs[cal_idx]
    else:
        cal_df = df
        cal_probs = probs

    export_tcp_udp_confusion_margin_summary(
        df=df,
        X=X,
        calibrated=artifacts["calibrated"],
        label_encoder=artifacts["label_encoder"],
        models_dir=models_dir,
        test_idx=split_indices["test"],
        results_dir=results_dir,
    )

    export_tcp_udp_entropy_brier_sanity(
        df=df,
        X=X,
        calibrated=artifacts["calibrated"],
        label_encoder=artifacts["label_encoder"],
        models_dir=models_dir,
        test_idx=split_indices["test"],
        results_dir=results_dir,
    )

    export_tcp_udp_hedging_threshold_tradeoff(
        alerts=alerts,
        df=df,
        X=X,
        calibrated=artifacts["calibrated"],
        label_encoder=artifacts["label_encoder"],
        models_dir=models_dir,
        test_idx=split_indices["test"],
        results_dir=results_dir,
    )

    export_tcp_udp_feature_separation(
        df=df,
        train_idx=split_indices["train"],
        results_dir=results_dir,
    )

    export_tcp_udp_hh_jit_overlap_reference(
        df=df,
        train_idx=split_indices["train"],
        test_idx=split_indices["test"],
        results_dir=results_dir,
    )

    export_calibration_summary(
        df=cal_df,
        probs=cal_probs,
        label_encoder=artifacts["label_encoder"],
        results_dir=results_dir,
        n_bins=args.calibration_bins,
        min_bin_size=args.min_reliability_bin_size,
    )
    export_tcp_udp_pair_calibration(
        df=cal_df,
        probs=cal_probs,
        label_encoder=artifacts["label_encoder"],
        results_dir=results_dir,
        n_bins=args.calibration_bins,
        min_bin_size=args.min_reliability_bin_size,
    )

    traffic_cols = traffic_feature_cols_from_df(df)
    export_benign_reference_stats(
        df=df,
        traffic_feature_cols=traffic_cols,
        out_path=results_dir / "benign_reference_stats.parquet",
    )

    if not args.skip_shap:
        export_shap_global_profiles(
            df=df,
            X=X,
            calibrated=artifacts["calibrated"],
            raw_model=artifacts["raw_model"],
            label_encoder=artifacts["label_encoder"],
            results_dir=results_dir,
            max_rows=args.shap_global_samples,
            random_state=args.random_state,
            top_k=args.shap_top_k,
        )
        export_tcp_udp_polarity_shap(
            df=df,
            X=X,
            calibrated=artifacts["calibrated"],
            raw_model=artifacts["raw_model"],
            label_encoder=artifacts["label_encoder"],
            results_dir=results_dir,
            chunk_size=args.shap_polarity_chunk_size,
        )


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export Module 1 explanation inputs for Module 2."
    )
    script_dir = Path(__file__).resolve().parent
    parser.add_argument(
        "--data-path",
        default=str(script_dir / "nbaiot_sampled.parquet"),
        help="Path to the sampled N-BaIoT parquet produced by dataloader.py.",
    )
    parser.add_argument(
        "--models-dir",
        default=str(script_dir / "models"),
        help="Directory containing Stage A and Stage B model artefacts.",
    )
    parser.add_argument(
        "--results-dir",
        default=str(script_dir / "results"),
        help="Directory for exported Module 1 outputs.",
    )
    parser.add_argument("--calibration-bins", type=int, default=10)
    parser.add_argument("--min-reliability-bin-size", type=int, default=100)
    parser.add_argument(
        "--calibration-split",
        choices=("test", "full"),
        default="test",
        help="Use the reconstructed held-out test split by default.",
    )
    parser.add_argument(
        "--shap-global-samples",
        type=int,
        default=5000,
        help="Stratified sample size for global SHAP profiles. Use <=0 for all rows.",
    )
    parser.add_argument(
        "--shap-top-k",
        type=int,
        default=5,
        help="Top-k feature families for SHAP sanity and atypicality diagnostics.",
    )
    parser.add_argument(
        "--shap-polarity-chunk-size",
        type=int,
        default=5000,
        help="Rows per TreeSHAP batch for the tcp/udp polarity diagnostic.",
    )
    parser.add_argument("--skip-shap", action="store_true")
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args(argv)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    run_exports(parse_args())
