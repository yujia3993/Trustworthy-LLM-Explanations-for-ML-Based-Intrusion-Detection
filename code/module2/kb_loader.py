"""Loaders and validators for the Module 2 knowledge base.

The knowledge base is a set of markdown documents with a restricted YAML
frontmatter block, a frozen metadata schema, and a frozen retrieval gold set.
Parsing uses no third-party YAML dependency: the frontmatter is deliberately
limited to scalars and JSON-style arrays so ``json`` can decode every value.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

KB_DIR = Path(__file__).resolve().parent / "kb"
DOCS_DIR = KB_DIR / "docs"
METADATA_SCHEMA_PATH = KB_DIR / "metadata_schema.json"
GOLD_SET_PATH = KB_DIR / "gold_set.json"

DEVICE_PROFILE_PLACEHOLDER = "DEVICE_PROFILE"


class KBValidationError(ValueError):
    """Raised when a KB document, the schema, or the gold set is malformed."""


@dataclass(frozen=True, slots=True)
class KBDocument:
    """One knowledge-base document: parsed frontmatter plus body text."""

    doc_id: str
    title: str
    attack_family: str
    attack_types: tuple[str, ...]
    device_categories: tuple[str, ...]
    doc_type: str
    source: str
    is_distractor: bool
    body: str
    path: Path


def load_metadata_schema() -> dict[str, Any]:
    """Load the frozen metadata schema."""

    with METADATA_SCHEMA_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _parse_frontmatter(text: str, path: Path) -> tuple[dict[str, Any], str]:
    """Split a document into its frontmatter mapping and body.

    The frontmatter is a ``---`` delimited block of ``key: value`` lines where
    every value is a JSON scalar (string, bool) or a JSON array of strings.
    """

    if not text.startswith("---"):
        raise KBValidationError(f"{path.name}: missing frontmatter opening '---'")
    lines = text.splitlines()
    if lines[0].strip() != "---":
        raise KBValidationError(f"{path.name}: first line must be exactly '---'")

    closing_index = None
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            closing_index = index
            break
    if closing_index is None:
        raise KBValidationError(f"{path.name}: missing frontmatter closing '---'")

    meta: dict[str, Any] = {}
    for raw in lines[1:closing_index]:
        if not raw.strip():
            continue
        if ":" not in raw:
            raise KBValidationError(f"{path.name}: malformed frontmatter line: {raw!r}")
        key, _, raw_value = raw.partition(":")
        key = key.strip()
        raw_value = raw_value.strip()
        meta[key] = _parse_scalar(raw_value, key, path)

    body = "\n".join(lines[closing_index + 1:]).strip()
    return meta, body


def _parse_scalar(raw_value: str, key: str, path: Path) -> Any:
    """Decode a single frontmatter value."""

    if raw_value in {"true", "false"}:
        return raw_value == "true"
    if raw_value.startswith("[") or raw_value.startswith('"'):
        try:
            return json.loads(raw_value)
        except json.JSONDecodeError as exc:
            raise KBValidationError(
                f"{path.name}: field {key!r} is not valid JSON: {raw_value!r}"
            ) from exc
    return raw_value


def _validate_against_schema(
    meta: dict[str, Any], body: str, path: Path, schema: dict[str, Any]
) -> None:
    """Check one document's frontmatter against the frozen schema."""

    fields = schema["fields"]
    missing = sorted(set(fields) - set(meta))
    if missing:
        raise KBValidationError(f"{path.name}: missing frontmatter fields: {missing!r}")
    unexpected = sorted(set(meta) - set(fields))
    if unexpected:
        raise KBValidationError(f"{path.name}: unexpected frontmatter fields: {unexpected!r}")

    for name, spec in fields.items():
        value = meta[name]
        expected_type = spec["type"]
        if expected_type == "string":
            if not isinstance(value, str) or not value:
                raise KBValidationError(f"{path.name}: {name!r} must be a non-empty string")
            if "enum" in spec and value not in spec["enum"]:
                raise KBValidationError(
                    f"{path.name}: {name!r}={value!r} not in enum {spec['enum']!r}"
                )
            if "pattern" in spec:
                import re

                if not re.fullmatch(spec["pattern"], value):
                    raise KBValidationError(
                        f"{path.name}: {name!r}={value!r} violates pattern {spec['pattern']!r}"
                    )
        elif expected_type == "boolean":
            if not isinstance(value, bool):
                raise KBValidationError(f"{path.name}: {name!r} must be a boolean")
        elif expected_type == "array[string]":
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise KBValidationError(f"{path.name}: {name!r} must be a list of strings")
            if "item_enum" in spec:
                bad = [v for v in value if v not in spec["item_enum"]]
                if bad:
                    raise KBValidationError(
                        f"{path.name}: {name!r} has values outside item_enum: {bad!r}"
                    )
        else:  # pragma: no cover - guards against schema drift
            raise KBValidationError(f"{path.name}: unknown schema type {expected_type!r}")

    if meta["doc_id"] != path.stem:
        raise KBValidationError(
            f"{path.name}: doc_id {meta['doc_id']!r} must equal filename stem {path.stem!r}"
        )
    if "is_distractor" in body.lower() or "distractor" in body.lower():
        raise KBValidationError(
            f"{path.name}: the word 'distractor' must not appear in body text (embedding leak)"
        )


def load_kb_docs(validate: bool = True) -> list[KBDocument]:
    """Load every KB document, validating against the frozen schema by default."""

    schema = load_metadata_schema()
    docs: list[KBDocument] = []
    seen_ids: set[str] = set()
    for path in sorted(DOCS_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        meta, body = _parse_frontmatter(text, path)
        if validate:
            _validate_against_schema(meta, body, path, schema)
        if meta["doc_id"] in seen_ids:
            raise KBValidationError(f"duplicate doc_id: {meta['doc_id']!r}")
        seen_ids.add(meta["doc_id"])
        docs.append(
            KBDocument(
                doc_id=meta["doc_id"],
                title=meta["title"],
                attack_family=meta["attack_family"],
                attack_types=tuple(meta["attack_types"]),
                device_categories=tuple(meta["device_categories"]),
                doc_type=meta["doc_type"],
                source=meta["source"],
                is_distractor=bool(meta["is_distractor"]),
                body=body,
                path=path,
            )
        )
    if not docs:
        raise KBValidationError(f"no KB documents found in {DOCS_DIR}")
    return docs


def load_gold_set() -> dict[str, Any]:
    """Load the frozen retrieval gold set."""

    with GOLD_SET_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def gold_set_referenced_doc_ids(gold_set: dict[str, Any]) -> set[str]:
    """Every concrete doc_id referenced by gold-set entries (placeholder excluded)."""

    referenced: set[str] = set()
    for sections in gold_set["entries"].values():
        for expected in sections.values():
            for doc_id in expected:
                if doc_id != DEVICE_PROFILE_PLACEHOLDER:
                    referenced.add(doc_id)
    return referenced
