"""Within-device univariate tcp/udp AUC diagnostic for H feature families."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from module1_exports import reconstruct_stage_b_split_indices


TCP = "gafgyt_tcp"
UDP = "gafgyt_udp"
TARGET_FAMILIES = ("H_weight", "H_variance")


def feature_family(name: str) -> str:
    """Map H_L0.01_weight to H_weight, preserving only the requested family."""
    parts = name.split("_")
    if len(parts) == 3 and parts[0] == "H" and parts[1].startswith("L"):
        return f"H_{parts[2]}"
    return name


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Compute per-device tcp-vs-udp univariate AUC for H families."
    )
    parser.add_argument("--data-path", default=str(script_dir / "nbaiot_sampled.parquet"))
    parser.add_argument("--models-dir", default=str(script_dir / "models"))
    parser.add_argument("--results-dir", default=str(script_dir / "results"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    df = pd.read_parquet(args.data_path)
    label_encoder = joblib.load(Path(args.models_dir) / "xgb_label_encoder.joblib")
    split = reconstruct_stage_b_split_indices(df, label_encoder)
    train = df.iloc[split["train"]]
    pair = train[train["label_type"].isin([TCP, UDP])].copy()
    features = [
        feature for feature in pair.columns
        if feature_family(feature) in TARGET_FAMILIES
    ]
    if not features:
        raise RuntimeError("No H_weight/H_variance features found in the sampled data.")

    rows = []
    for device_name, device_df in pair.groupby("device_name", sort=True):
        y_udp = (device_df["label_type"] == UDP).astype(int).to_numpy()
        n_tcp = int((y_udp == 0).sum())
        n_udp = int((y_udp == 1).sum())
        if not n_tcp or not n_udp:
            continue
        for feature in features:
            auc_udp = float(roc_auc_score(y_udp, device_df[feature].to_numpy()))
            rows.append({
                "device_name": device_name,
                "feature_family": feature_family(feature),
                "feature": feature,
                "n_tcp": n_tcp,
                "n_udp": n_udp,
                "auc_udp": auc_udp,
                "separation_auc": max(auc_udp, 1.0 - auc_udp),
                "higher_value_class": UDP if auc_udp >= 0.5 else TCP,
            })

    result = pd.DataFrame(rows).sort_values(
        ["feature_family", "device_name", "feature"]
    )
    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    result.to_csv(results_dir / "tcp_udp_h_per_device_auc.csv", index=False)

    summary = (
        result.groupby(["feature_family", "feature"], as_index=False)
        .agg(
            n_devices=("device_name", "nunique"),
            median_auc_udp=("auc_udp", "median"),
            min_auc_udp=("auc_udp", "min"),
            max_auc_udp=("auc_udp", "max"),
            median_separation_auc=("separation_auc", "median"),
            min_separation_auc=("separation_auc", "min"),
            max_separation_auc=("separation_auc", "max"),
        )
        .sort_values(["feature_family", "feature"])
    )
    summary.to_csv(results_dir / "tcp_udp_h_per_device_auc_summary.csv", index=False)
    (results_dir / "tcp_udp_h_per_device_auc_metadata.json").write_text(
        json.dumps({
            "split": "reconstructed Stage B training split",
            "positive_class_for_auc_udp": UDP,
            "interpretation": (
                "auc_udp near 0.5 means no within-device ranking signal; "
                "separation_auc removes direction so a value near 1 means strong "
                "within-device separation in either direction."
            ),
            "n_pair_train_rows": int(len(pair)),
        }, indent=2),
        encoding="utf-8",
    )
    print(summary.to_string(index=False))


if __name__ == "__main__":
    main()
