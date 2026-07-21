"""Validation tests for the frozen knowledge base and retrieval gold set."""

from __future__ import annotations

import pytest

from ..kb_loader import (
    DEVICE_PROFILE_PLACEHOLDER,
    KBValidationError,
    gold_set_referenced_doc_ids,
    load_gold_set,
    load_kb_docs,
    load_metadata_schema,
)

EXPECTED_CORE_DOCS = 28
EXPECTED_DISTRACTORS = 10
EXPECTED_TOTAL = EXPECTED_CORE_DOCS + EXPECTED_DISTRACTORS

ATTACK_TYPES = {
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
}
REPORT_SECTIONS = {
    "threat_assessment",
    "attack_mechanism",
    "observable_indicators",
    "immediate_actions",
    "longer_term_remediation",
    "confidence_notes",
}


@pytest.fixture(scope="module")
def docs():
    return load_kb_docs()


@pytest.fixture(scope="module")
def gold_set():
    return load_gold_set()


def test_all_docs_parse_and_validate(docs):
    # load_kb_docs validates each document; reaching here means all passed.
    assert len(docs) == EXPECTED_TOTAL


def test_core_and_distractor_counts(docs):
    core = [d for d in docs if not d.is_distractor]
    distractors = [d for d in docs if d.is_distractor]
    assert len(core) == EXPECTED_CORE_DOCS
    assert len(distractors) == EXPECTED_DISTRACTORS


def test_doc_ids_unique_and_match_filenames(docs):
    ids = [d.doc_id for d in docs]
    assert len(ids) == len(set(ids))
    for d in docs:
        assert d.doc_id == d.path.stem


def test_distractor_ratio_within_target_band(docs):
    ratio = sum(d.is_distractor for d in docs) / len(docs)
    assert 0.20 <= ratio <= 0.30, f"distractor ratio {ratio:.3f} outside [0.20, 0.30]"


def test_gold_set_covers_all_attack_types_and_sections(gold_set):
    entries = gold_set["entries"]
    assert set(entries) == ATTACK_TYPES
    for attack_type, sections in entries.items():
        assert set(sections) == REPORT_SECTIONS, f"{attack_type} section mismatch"


def test_gold_set_references_only_existing_non_distractor_docs(docs, gold_set):
    by_id = {d.doc_id: d for d in docs}
    referenced = gold_set_referenced_doc_ids(gold_set)
    assert referenced, "gold set references no documents"
    for doc_id in referenced:
        assert doc_id in by_id, f"gold set references unknown doc_id {doc_id!r}"
        assert not by_id[doc_id].is_distractor, f"gold set references distractor {doc_id!r}"


def test_gold_set_cells_are_bounded(gold_set):
    for attack_type, sections in gold_set["entries"].items():
        for section, expected in sections.items():
            assert isinstance(expected, list)
            assert len(expected) <= 5, f"{attack_type}/{section} exceeds Recall@5 window"
            assert len(expected) == len(set(expected)), f"{attack_type}/{section} has duplicates"


def test_ambiguous_pair_has_confidence_and_pcap_docs(gold_set):
    pair = gold_set["ambiguous_pair"]["members"]
    assert set(pair) == {"gafgyt_tcp", "gafgyt_udp"}
    for member in pair:
        entry = gold_set["entries"][member]
        assert "finding-pair-level-assertion" in entry["confidence_notes"]
        assert "finding-no-protocol-field" in entry["confidence_notes"]
        assert "finding-pcap-disambiguation" in entry["immediate_actions"]


def test_assertive_classes_have_empty_confidence_notes(gold_set):
    assertive = ATTACK_TYPES - {"gafgyt_tcp", "gafgyt_udp"}
    for attack_type in assertive:
        assert gold_set["entries"][attack_type]["confidence_notes"] == []


def test_device_profile_placeholder_resolves(gold_set, docs):
    by_id = {d.doc_id for d in docs}
    resolution = gold_set["device_profile_resolution"]
    for category, doc_id in resolution.items():
        assert doc_id in by_id, f"device profile {doc_id!r} for {category!r} missing"


def test_device_category_map_targets_known_categories(gold_set):
    schema = load_metadata_schema()
    categories = set(gold_set["device_profile_resolution"])
    mapped = set(schema["device_category_map"].values())
    assert mapped == categories


def test_attack_mechanism_docs_exist_for_every_attack_type(docs, gold_set):
    by_id = {d.doc_id: d for d in docs}
    for attack_type, sections in gold_set["entries"].items():
        mechanism_docs = [
            doc_id
            for doc_id in sections["attack_mechanism"]
            if doc_id != DEVICE_PROFILE_PLACEHOLDER
        ]
        # The class-specific mechanism doc must declare this attack_type.
        assert any(
            attack_type in by_id[doc_id].attack_types for doc_id in mechanism_docs
        ), f"no mechanism doc declares {attack_type}"


def test_distractor_word_absent_from_bodies(docs):
    for d in docs:
        assert "distractor" not in d.body.lower()


def test_frozen_flags_set(gold_set):
    assert gold_set["frozen"] is True
    assert load_metadata_schema()["frozen"] is True


def test_malformed_frontmatter_raises(tmp_path):
    from ..kb_loader import _parse_frontmatter

    with pytest.raises(KBValidationError):
        _parse_frontmatter("no frontmatter here", tmp_path / "x.md")
