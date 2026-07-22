"""Filesystem cache for validated claim extraction results."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .claims import Claim


DEFAULT_CLAIM_CACHE_DIR = Path(__file__).resolve().parent / "claim_cache"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ClaimCache:
    def __init__(self, dir: str | Path = DEFAULT_CLAIM_CACHE_DIR) -> None:
        self.dir = Path(dir)
        self.directory = self.dir
        self.directory.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def key(model: str | None, claim_prompt: str, report_md: str) -> str:
        raw = json.dumps(
            [model, _sha256(claim_prompt), _sha256(report_md)],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _path(self, model: str | None, claim_prompt: str, report_md: str) -> Path:
        return self.directory / f"{self.key(model, claim_prompt, report_md)}.json"

    def get(
        self, model: str | None, claim_prompt: str, report_md: str
    ) -> list[Claim] | None:
        path = self._path(model, claim_prompt, report_md)
        if not path.exists():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        expected = {
            "model": model,
            "claim_prompt_sha256": _sha256(claim_prompt),
            "report_sha256": _sha256(report_md),
        }
        if not isinstance(entry, dict) or any(
            entry.get(key) != value for key, value in expected.items()
        ):
            return None

        claims = entry.get("claims")
        if not isinstance(claims, list):
            return None
        from .claims import EvalParseError, parse_claims_json

        try:
            return parse_claims_json(json.dumps(claims, ensure_ascii=False))
        except EvalParseError:
            return None

    def put(
        self,
        claims: list[Claim],
        model: str | None,
        claim_prompt: str,
        report_md: str,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "claims": [
                {
                    "text": claim.text,
                    "section": claim.section,
                    "type": claim.type,
                    "cited_refs": list(claim.cited_refs),
                    "label": claim.label,
                }
                for claim in claims
            ],
            "model": model,
            "claim_prompt_sha256": _sha256(claim_prompt),
            "report_sha256": _sha256(report_md),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        path = self._path(model, claim_prompt, report_md)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(entry, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        temporary.replace(path)
        return entry
