"""Heading-aware chunking for the frozen Module 2 knowledge base."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..kb_loader import KBDocument

MIN_SECTION_WORDS = 60
_LEVEL_TWO_HEADING = re.compile(r"(?m)^## .+$")


@dataclass(frozen=True, slots=True)
class Chunk:
    """A retrievable KB passage and its document-level metadata."""

    chunk_id: str
    doc_id: str
    section_heading: str
    text: str
    attack_family: str
    attack_types: tuple[str, ...]
    device_categories: tuple[str, ...]
    doc_type: str
    source: str
    is_distractor: bool
    title: str


@dataclass(slots=True)
class _Section:
    heading: str
    text: str


def _word_count(text: str) -> int:
    return len(text.split())


def _split_sections(doc: KBDocument) -> list[_Section]:
    """Split a body at level-two headings while retaining each heading."""

    matches = list(_LEVEL_TWO_HEADING.finditer(doc.body))
    if not matches:
        return [_Section(doc.title, doc.body.strip())]

    sections = [_Section(doc.title, doc.body[: matches[0].start()].strip())]
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(doc.body)
        text = doc.body[match.start() : end].strip()
        heading = match.group()[3:].strip()
        sections.append(_Section(heading, text))
    return [section for section in sections if section.text]


def _merge_short_sections(sections: list[_Section]) -> list[_Section]:
    """Merge a short heading section backward, preserving heading boundaries in text."""

    if len(sections) <= 1:
        return sections

    merged: list[_Section] = []
    for section in sections:
        if merged and _word_count(section.text) < MIN_SECTION_WORDS:
            previous = merged[-1]
            previous.text = f"{previous.text}\n\n{section.text}"
        else:
            merged.append(section)
    return merged


def chunk_documents(docs: list[KBDocument]) -> list[Chunk]:
    """Create deterministic, heading-granularity chunks from KB documents.

    The loader has already removed frontmatter. Level-two sections below roughly
    60 words are folded into their predecessor; the introductory section is kept
    independently when there is no predecessor to receive it.
    """

    chunks: list[Chunk] = []
    for doc in docs:
        sections = _merge_short_sections(_split_sections(doc))
        for index, section in enumerate(sections):
            chunks.append(
                Chunk(
                    chunk_id=f"{doc.doc_id}#{index}",
                    doc_id=doc.doc_id,
                    section_heading=section.heading,
                    text=section.text,
                    attack_family=doc.attack_family,
                    attack_types=doc.attack_types,
                    device_categories=doc.device_categories,
                    doc_type=doc.doc_type,
                    source=doc.source,
                    is_distractor=doc.is_distractor,
                    title=doc.title,
                )
            )
    return chunks
