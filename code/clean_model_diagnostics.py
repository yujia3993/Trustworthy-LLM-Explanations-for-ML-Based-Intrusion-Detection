"""Diagnostics for the canonical clean Stage B model."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

from module1_exports import (
    reconstruct_stage_b_split_indices,
    top2_from_probs,
    entropy_nats,
    prepare_stage_b_features,
)
from train_stage_b import run_stage_a_on_test

logger = logging.getLogger(__name__)

TCP_UDP_CLASSES = ("gafgyt_tcp", "gafgyt_udp")


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")


def load_artifacts(models_dir: Path) -> dict[str, object]:
    return {
        "calibrated": joblib.load(models_dir / "xgb_stage_b.joblib"),
        "label_encoder": joblib.load(models_dir / "xgb_label_encoder.joblib"),
        "feature_cols": joblib.load(models_dir / "xgb_feature_cols.joblib"),
    }


def class_metrics_by_device(
    df_test: pd.DataFrame,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: np.ndarray,
    results_dir: Path,
) -> pd.DataFrame:
    rows = []
    for device, idx in df_test.groupby("device_name").groups.items():
        idx = np.asarray(list(idx))
        for class_idx, class_name in enumerate(class_names):
            mask = y_true[idx] == class_idx
            if not mask.any():
                continue
            local_pred = y_pred[idx][mask]
            recall = float((local_pred == class_idx).mean())
            rows.append({
                "device_name": device,
                "class": class_name,
                "support": int(mask.sum()),
                "recall": recall,
            })
    out = pd.DataFrame(rows)
    out.to_csv(results_dir / "stage_b_clean_per_device_recall.csv", index=False)

    tcp_udp = out[out["class"].isin(TCP_UDP_CLASSES)] 
    tcp_udp.to_csv(
        results_dir / "stage_b_clean_tcp_udp_per_device_recall.csv",
        index=False,
    )
    return out


def margin_band_tables(
    df_test: pd.DataFrame,
    probs: np.ndarray,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: np.ndarray,
    results_dir: Path,
) -> None:
    _, pred_names, p_top1, top2_names, p_top2 = top2_from_probs(probs, class_names)
    margins = p_top1 - p_top2
    test_alerts = pd.DataFrame({
        "sample_id": df_test["sample_id"].to_numpy()
        if "sample_id" in df_test.columns else df_test.index.to_numpy(),
        "device_name": df_test["device_name"].to_numpy(),
        "label_type": df_test["label_type"].to_numpy(),
        "y_pred": pred_names,
        "top2_class": top2_names,
        "p_top1": p_top1,
        "p_top2": p_top2,
        "margin": margins,
        "entropy": entropy_nats(probs),
        "correct": y_true == y_pred,
    })
    test_alerts = test_alerts[df_test["label_binary"].to_numpy() == 1].copy()

    bins = pd.cut(
        test_alerts["margin"],
        [0.0, 0.5, 0.9, 0.99, 1.0],
        include_lowest=True,
    )
    band = (
        test_alerts.groupby(bins, observed=False)
        .agg(
            n=("sample_id", "size"),
            error_rate=("correct", lambda s: float((~s).mean())),
            tcp_udp_frac=(
                "label_type",
                lambda s: float(s.isin(TCP_UDP_CLASSES).mean()),
            ),
            median_entropy=("entropy", "median"),
            p90_entropy=("entropy", lambda s: float(s.quantile(0.90))),
        )
        .reset_index()
        .rename(columns={"margin": "margin_band"})
    )
    band["hedged_candidate"] = band["margin_band"].astype(str)
    band.to_csv(results_dir / "stage_b_clean_margin_band_summary.csv", index=False)

    tcp_idx = int(np.where(class_names == TCP_UDP_CLASSES[0])[0][0])
    udp_idx = int(np.where(class_names == TCP_UDP_CLASSES[1])[0][0])
    tcp_udp_true = np.isin(y_true, [tcp_idx, udp_idx])
    tcp_udp_error = tcp_udp_true & (y_true != y_pred)
    thresholds = [0.5, 0.7, 0.8, 0.9, 0.95, 0.99]
    rows = []
    for threshold in thresholds:
        hedged = margins <= threshold
        rows.append({
            "margin_threshold": threshold,
            "hedged_n_all_alerts": int((hedged & (df_test["label_binary"].to_numpy() == 1)).sum()),
            "hedged_frac_all_alerts": float(
                (hedged & (df_test["label_binary"].to_numpy() == 1)).sum()
                / max((df_test["label_binary"].to_numpy() == 1).sum(), 1)
            ),
            "tcp_udp_error_capture_rate": float(
                (hedged & tcp_udp_error).sum() / max(tcp_udp_error.sum(), 1)
            ),
            "hedged_tcp_udp_n": int((hedged & tcp_udp_true).sum()),
            "hedged_tcp_udp_error_rate": float(
                (hedged & tcp_udp_error).sum() / max((hedged & tcp_udp_true).sum(), 1)
            ),
            "tcp_udp_error_total": int(tcp_udp_error.sum()),
        })
    pd.DataFrame(rows).to_csv(
        results_dir / "stage_b_clean_hedging_threshold_tradeoff.csv",
        index=False,
    )


def top_confusion_pairs(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: np.ndarray,
    results_dir: Path,
    top_n: int = 8,
) -> list[tuple[str, str]]:
    cm = confusion_matrix(y_true, y_pred, labels=np.arange(len(class_names)))
    rows = []
    pairs = {TCP_UDP_CLASSES}
    for i, true_class in enumerate(class_names):
        for j, pred_class in enumerate(class_names):
            if i == j:
                continue
            n = int(cm[i, j])
            if n:
                rows.append({
                    "true_class": true_class,
                    "pred_class": pred_class,
                    "n": n,
                })
    pairs_df = pd.DataFrame(rows).sort_values("n", ascending=False)
    pairs_df.to_csv(results_dir / "stage_b_clean_top_confusion_pairs.csv", index=False)
    for _, row in pairs_df.head(top_n).iterrows():
        pairs.add((row["true_class"], row["pred_class"]))
    return sorted({tuple(sorted(pair)) for pair in pairs})


def residual_fingerprint_audit(
    df_test: pd.DataFrame,
    y_true: np.ndarray,
    pairs: list[tuple[str, str]],
    class_names: np.ndarray,
    feature_cols: list[str],
    results_dir: Path,
    top_k: int = 8,
) -> None:
    profiles_path = results_dir / "shap_global_profiles.parquet"
    if not profiles_path.exists():
        logger.warning("Skipping fingerprint audit; missing %s", profiles_path)
        return

    profiles = pd.read_parquet(profiles_path)
    rows = []
    pair_rows = []
    for class_a, class_b in pairs:
        if class_a not in class_names or class_b not in class_names:
            continue
        idx_a = int(np.where(class_names == class_a)[0][0])
        idx_b = int(np.where(class_names == class_b)[0][0])
        mask_a = y_true == idx_a
        mask_b = y_true == idx_b
        pair_rows.append({
            "class_a": class_a,
            "class_b": class_b,
            "support_a": int(mask_a.sum()),
            "support_b": int(mask_b.sum()),
        })

        top_features = (
            profiles[profiles["class"].isin([class_a, class_b])]
            .sort_values("mean_abs_shap", ascending=False)
            .drop_duplicates("representative_feature")
            .head(top_k)["representative_feature"]
            .tolist()
        )
        for feature in top_features:
            if feature not in feature_cols or feature not in df_test.columns:
                continue
            a = df_test.loc[mask_a, feature].to_numpy(dtype=float)
            b = df_test.loc[mask_b, feature].to_numpy(dtype=float)
            if len(a) == 0 or len(b) == 0:
                continue
            a_min, a_max = float(np.nanmin(a)), float(np.nanmax(a))
            b_min, b_max = float(np.nanmin(b)), float(np.nanmax(b))
            a_p10, a_p90 = float(np.nanquantile(a, 0.10)), float(np.nanquantile(a, 0.90))
            b_p10, b_p90 = float(np.nanquantile(b, 0.10)), float(np.nanquantile(b, 0.90))
            complete_gap = (a_max < b_min) or (b_max < a_min)
            central_gap = (a_p90 < b_p10) or (b_p90 < a_p10)
            rows.append({
                "class_a": class_a,
                "class_b": class_b,
                "feature": feature,
                "a_median": float(np.nanmedian(a)),
                "a_p10": a_p10,
                "a_p90": a_p90,
                "a_min": a_min,
                "a_max": a_max,
                "b_median": float(np.nanmedian(b)),
                "b_p10": b_p10,
                "b_p90": b_p90,
                "b_min": b_min,
                "b_max": b_max,
                "complete_nonoverlap": bool(complete_gap),
                "central_p10_p90_gap": bool(central_gap),
                "review_flag": bool(complete_gap),
            })

    pd.DataFrame(pair_rows).to_csv(
        results_dir / "residual_fingerprint_pairs.csv",
        index=False,
    )
    audit = pd.DataFrame(rows)
    if not audit.empty:
        audit = audit.sort_values(
            ["review_flag", "central_p10_p90_gap", "class_a", "class_b"],
            ascending=[False, False, True, True],
        )
    audit.to_csv(results_dir / "residual_fingerprint_audit.csv", index=False)


def stage_a_delta(results_dir: Path) -> None:
    before = results_dir / "stage_a_summary_pre_clean.csv"
    after = results_dir / "stage_a_summary.csv"
    if not before.exists() or not after.exists():
        return
    old = pd.read_csv(before)
    new = pd.read_csv(after)
    merged = old.merge(new, on="device_name", suffixes=("_pre_clean", "_clean"))
    for col in ("benign_fpr", "attack_recall"):
        merged[f"{col}_delta"] = merged[f"{col}_clean"] - merged[f"{col}_pre_clean"]
    merged.to_csv(results_dir / "stage_a_clean_delta.csv", index=False)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    script_dir = Path(__file__).resolve().parent
    data_path = script_dir / "nbaiot_sampled.parquet"
    models_dir = script_dir / "models"
    results_dir = script_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_parquet(data_path)
    if "sample_id" not in df.columns:
        df = df.copy()
        df["sample_id"] = df.index

    artifacts = load_artifacts(models_dir)
    le = artifacts["label_encoder"]
    class_names = le.classes_
    X = prepare_stage_b_features(df, artifacts["feature_cols"])
    splits = reconstruct_stage_b_split_indices(df, le)
    test_idx = splits["test"]
    df_test = df.iloc[test_idx].reset_index(drop=True)
    X_test = X.iloc[test_idx].reset_index(drop=True)
    y_true = le.transform(df_test["label_type"].to_numpy())

    probs = artifacts["calibrated"].predict_proba(X_test)
    y_pred = probs.argmax(axis=1)
    stage_a_flags = run_stage_a_on_test(df_test, models_dir)

    class_metrics_by_device(df_test, y_true, y_pred, class_names, results_dir)
    margin_band_tables(df_test, probs, y_true, y_pred, class_names, results_dir)
    pairs = top_confusion_pairs(y_true, y_pred, class_names, results_dir)
    residual_fingerprint_audit(
        df_test=df_test,
        y_true=y_true,
        pairs=pairs,
        class_names=class_names,
        feature_cols=artifacts["feature_cols"],
        results_dir=results_dir,
    )
    stage_a_delta(results_dir)

    summary = {
        "n_test": int(len(df_test)),
        "stage_a_flagged_frac": float(stage_a_flags.mean()),
        "stage_b_accuracy": float((y_true == y_pred).mean()),
        "confusion_pairs_for_fingerprint": [
            {"class_a": a, "class_b": b} for a, b in pairs
        ],
    }
    (results_dir / "clean_model_diagnostics_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
