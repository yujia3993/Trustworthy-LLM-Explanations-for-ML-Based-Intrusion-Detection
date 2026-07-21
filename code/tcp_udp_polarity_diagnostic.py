"""Standalone SHAP contrast diagnostic for predicted gafgyt tcp/udp samples."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import pandas as pd

from module1_exports import (
    export_tcp_udp_polarity_shap,
    load_artifacts,
    prepare_stage_b_features,
)


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Export SHAP(tcp) - SHAP(udp) for predicted tcp/udp samples."
    )
    parser.add_argument("--data-path", default=str(script_dir / "nbaiot_sampled.parquet"))
    parser.add_argument("--models-dir", default=str(script_dir / "models"))
    parser.add_argument("--results-dir", default=str(script_dir / "results"))
    parser.add_argument("--chunk-size", type=int, default=5000)
    parser.add_argument(
        "--max-rows",
        type=int,
        default=10000,
        help="Deterministic, device-balanced SHAP sample; use 0 for all rows.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.chunk_size <= 0:
        raise ValueError("--chunk-size must be positive")

    df = pd.read_parquet(args.data_path)
    artifacts = load_artifacts(Path(args.models_dir))
    X = prepare_stage_b_features(df, artifacts["feature_cols"])
    export_tcp_udp_polarity_shap(
        df=df,
        X=X,
        calibrated=artifacts["calibrated"],
        raw_model=artifacts["raw_model"],
        label_encoder=artifacts["label_encoder"],
        results_dir=Path(args.results_dir),
        chunk_size=args.chunk_size,
        max_rows=None if args.max_rows == 0 else args.max_rows,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    main()
