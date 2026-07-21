"""Frozen configuration for the Module 1 export contract."""

from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

REGISTER_THRESHOLD = 0.9
CLASS_ORDER = (
    "benign",
    "gafgyt_combo",
    "gafgyt_junk",
    "gafgyt_scan",
    "gafgyt_tcp",
    "gafgyt_udp",
    "mirai_ack",
    "mirai_scan",
    "mirai_syn",
    "mirai_udp",
    "mirai_udpplain",
)
AMBIGUOUS_PAIR = ("gafgyt_tcp", "gafgyt_udp")
