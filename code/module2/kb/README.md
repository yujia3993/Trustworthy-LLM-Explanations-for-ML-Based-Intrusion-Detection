# Module 2 Knowledge Base

Retrieval-augmented explanation knowledge base for the intrusion-detection reporting
layer. All contents here are **frozen** before retrieval ingestion and tuning.

## Layout

```
kb/
├── metadata_schema.json   # frozen metadata schema (v1.0.0) + device_category_map
├── gold_set.json          # frozen retrieval gold set (v1.0.0)
└── docs/                  # 38 markdown documents (28 core + 10 distractors)
```

Load and validate everything via `code/module2/kb_loader.py`
(`load_kb_docs`, `load_gold_set`, `load_metadata_schema`). Tests live in
`code/module2/tests/test_kb.py`.

## Documents

Each `docs/*.md` file has a restricted-YAML frontmatter block (scalars and JSON-style
string arrays only, so no YAML dependency is needed) followed by markdown body. The
frontmatter fields and their enums are defined and enforced by `metadata_schema.json`.

The 28 core documents cover: 2 family overviews, 10 attack-mechanism docs (one per
N-BaIoT attack class), 5 device profiles (one per device category), 4 remediation guides,
4 project-finding docs (this project's own conclusions), and 3 concept docs.

The 10 distractor documents are real but off-target (other botnet families, near-duplicate
variants absent from the dataset, plausible-but-misapplied remediation, out-of-scope
device classes). They exist so retrieval is fallible and the ablation has measurable
headroom. The `is_distractor` flag lives **only** in metadata — the word never appears in
any `doc_id`, title, or body (the loader enforces this, since it would leak into
embeddings). Current ratio: 10/38 ≈ 26%.

## Frozen policy

`metadata_schema.json` and `gold_set.json` both carry `"frozen": true`. Changing either
requires a new version and invalidates prior retrieval comparisons. Freeze the schema
before ingestion and the gold set before any retrieval tuning (git commit is the freeze
point).

## The DEVICE_PROFILE convention

The gold set (`gold_set.json`) is defined at **attack_type granularity** (10 attack types
× 6 report sections). Where a device profile is expected, entries contain the placeholder
token `"DEVICE_PROFILE"` rather than a specific profile doc. At evaluation time it resolves
to the profile for the alert's device via `device_category_map` (in `metadata_schema.json`)
→ `device_profile_resolution` (in `gold_set.json`). This keeps the gold set independent of
which of the 9 devices raised a given alert.

## Ambiguous pair handling

`gafgyt_tcp` and `gafgyt_udp` are statistically indistinguishable in the N-BaIoT feature
space. Their gold-set entries carry the pair-handling findings
(`finding-pair-level-assertion`, `finding-no-protocol-field`) in `confidence_notes` and
`finding-pcap-disambiguation` in `immediate_actions`. All other (assertive) classes have
empty `confidence_notes`, because confidence there comes from the model's calibrated
probability, not from retrieval.

## Not yet done (next task)

Expansion to 300+ retrieval chunks with external material (MITRE ATT&CK, public analyses,
CVEs, vendor advisories), chunking, embedding, and ChromaDB ingestion happen in the
retrieval task. This directory currently holds only the frozen self-authored core plus
seeded distractors.
