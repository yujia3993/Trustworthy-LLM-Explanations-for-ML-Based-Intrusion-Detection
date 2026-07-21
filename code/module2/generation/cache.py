"""Filesystem cache for completed, non-fallback generation results."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_CACHE_DIR = Path(__file__).resolve().parent / "cache"


class ReportCache:
    def __init__(self, dir: str | Path = DEFAULT_CACHE_DIR) -> None:
        self.dir = Path(dir)
        self.directory = self.dir
        self.directory.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def key(config_name: str, case_id: str, prompt_version: str) -> str:
        raw = f"{config_name}|{case_id}|{prompt_version}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _path(self, config_name: str, case_id: str, prompt_version: str) -> Path:
        return self.directory / f"{self.key(config_name, case_id, prompt_version)}.json"

    def get(
        self, config_name: str, case_id: str, prompt_version: str
    ) -> dict[str, Any] | None:
        path = self._path(config_name, case_id, prompt_version)
        if not path.exists():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        expected = {
            "config_name": config_name,
            "case_id": case_id,
            "prompt_version": prompt_version,
        }
        if not isinstance(entry, dict) or any(
            entry.get(key) != value for key, value in expected.items()
        ):
            return None
        return entry

    def put(
        self,
        report_md: str,
        register: str,
        config_name: str,
        case_id: str,
        prompt_version: str,
        model: str | None,
    ) -> dict[str, Any]:
        entry = {
            "report_md": report_md,
            "register": register,
            "config_name": config_name,
            "case_id": case_id,
            "prompt_version": prompt_version,
            "model": model,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        path = self._path(config_name, case_id, prompt_version)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
        return entry
