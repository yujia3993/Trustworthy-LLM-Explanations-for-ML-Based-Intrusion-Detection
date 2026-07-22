# Project State

**Trustworthy LLM Explanations for ML-Based Intrusion Detection (N-BaIoT)**
Snapshot: 2026-07-22 · Branch `main` · 78 tests passing

This is the working-state document (progress, decisions, what's next). For the
research narrative and headline results see [README.md](README.md).

---

## 1. Status at a glance

| Module | Scope | State |
|---|---|---|
| **Module 1** | Two-stage detector + leakage audit + explainability exports | ✅ Complete, sealed (pre-existing) |
| **Module 2** | RAG explanation layer (KB, retrieval, generation) | ✅ Infrastructure complete |
| **Module 3** | Evaluation (case set, harness, metrics) | ✅ Harness complete; ⏳ real-LLM runs pending |

**Blocking item for progress:** real-LLM evaluation runs need API keys (see §5).
Everything up to that point is built, committed, and tested with mock clients.

---


## 2. Module 2 — what exists

All under [code/module2/](code/module2/). Entry contract to Module 1 is
`contracts.py` (validated loaders for `alerts_full`, benign reference stats, SHAP
profiles) + `config.py` (`CLASS_ORDER`, `REGISTER_THRESHOLD=0.9`, `AMBIGUOUS_PAIR`).

### Knowledge base — FROZEN v1.0.0 
- `kb/metadata_schema.json` — field enums + 9-device→5-category map.
- `kb/docs/` — 38 markdown docs: **28 core** (2 family overviews, 10 attack
  mechanisms, 5 device profiles, 4 remediation, 4 project findings, 3 concepts) +
  **10 distractors** (26%, off-target by design so retrieval is fallible).
- `kb/gold_set.json` — 10 attack types × 6 report sections; `DEVICE_PROFILE`
  placeholder resolved per-device at eval time; ambiguous-pair special handling.
- Loader: `kb_loader.py` (dependency-free frontmatter parsing + schema validation).

### Retrieval 
- `chunking.py` → 117 chunks (heading-aware). `ingest.py` → ChromaDB index at
  `retrieval/index/` (gitignored, rebuild via `python -m module2.retrieval.ingest`).
- `retrievers.py` — 4-config ablation ladder with soft metadata preference:
  `CONFIG_DENSE` → `CONFIG_HYBRID` (+BM25/RRF) → `CONFIG_RERANK` (+cross-encoder)
  → `CONFIG_FULL` (+per-section query decomposition).
- `evaluate.py` — 300-query grid vs the frozen gold set. **Baseline Recall@5 / MRR:**

  | config | Recall@5 | MRR |
  |---|---|---|
  | dense | 0.385 | 0.601 |
  | +BM25/RRF | 0.355 | 0.550 |
  | +rerank | 0.369 | 0.588 |
  | **+decomposition (full)** | **0.504** | **0.653** |

  Results in `retrieval/*.csv`. Query decomposition is the dominant contributor;
  BM25 fusion is slightly negative — logged for failure analysis, **not** tuned
  (gold set is frozen).

### Generation 
- **Prompts (self-authored, frozen v1.0.0)** in `generation/prompts/`: system
  grounding rules, per-section instructions, three register blocks, self-check
  loop, evidence templates with locked number formats (probabilities 4dp).
- **Register logic** (`registers.py`): `assertive` (margin≥0.9) / `hedged_pair`
  (ambiguous gafgyt tcp/udp) / `hedged_generic`; `needs_review` runtime guard.
- **Pipeline** (`pipeline.py`): 4 presets `GEN_NO_RAG` / `GEN_NAIVE_RAG` /
  `GEN_FULL_RAG` / `GEN_SELF_CHECK`. `llm_client.py`: OpenAI-compatible client +
  register-aware `MockLLMClient` + retrieval-only fallback. Cache keyed
  `sha256(config|case_id|prompt_version)`.
- **RQ2 audit gates** (`audit.py` + `audit_rules.json`): (1) register↔margin
  mapping, (2) hedged disclosures present, (3) no within-pair ordering language,
  (4) probability-string consistency. Machine-checkable.
- Human-readable register spec: `generation/README.md`.

---

## 3. Module 3 — what exists

Under [code/module2/evaluation/](code/module2/evaluation/).

### Evaluation case set — FROZEN v1.0.0 
- `sampling_plan.md` — design authority. Held-out-test-split only, seed-42
  deterministic. **Evidence screen rule v1**: discriminative requires
  supports-pred + (z≥3 or >p99); **ambiguous-pair alerts are blanket contextual**
  (SHAP prominence ≠ evidential value).
- `cases/eval_cases_frozen.json` — **101 cases**: 56 assertive-correct /
  3 assertive-error (the known high-confidence errors) / 36 hedged-pair (18-18
  truth-balanced) / 6 hedged-generic. All 9 devices covered.
- `cases/eval_cases_dev.json` — **14 cases** (case set v1.1.0, sampling plan
  v1.1.0): 8 assertive-correct / 4 hedged-pair / **2 hedged-generic**, disjoint
  from frozen by `sample_id`. The 2 hedged-generic cases were added so a dev
  smoke exercises **all three** register paths; before that, `hedged_generic`
  would have met a real model for the first time during the frozen run.
  Dev **cannot** contain `assertive_error` — the held-out pool holds only 3 and
  all 3 are in the frozen set. Harmless: that stratum shares the `assertive`
  register with `assertive_correct`, so no register path is left untested.
- `export_cases.py` — idempotent (byte-identical re-runs) via
  `module1_exports.explain_alert`.

### Evaluation harness 
- **Protocol (self-authored, frozen v1.0.0)** `eval_protocol.md`: three-way claim
  taxonomy (`supported` / `unsupported_but_true` / `unsupported_and_false` —
  faithfulness and factuality as separate axes), claim-type scoring routes,
  machine-verification rules, judge rubric, RQ3 κ design. Prompts:
  `prompts/claim_extraction.md`, `prompts/judge.md`. `judge_rubric.json`.
- `feature_verify.py` — **deterministic** feature-claim checks (fabricated
  numbers, invalid [E#]/[C#] refs, contextual misuse). Verified zero false
  positives on real frozen cases.
- `claims.py` (extractor + mock), `judge.py` (env-separate judge client + cache +
  mock), `metrics.py` (taxonomy aggregation + Cohen's/weighted κ),
  `run_eval.py` (4-config orchestrator → summary/claims/RQ2 CSVs),
  `rq3_sheet.py` (20-case human scoring sheet).
- Mock dev run validated the mechanics: **48/48 RQ2 audits pass**. The mock output
  CSVs *are* committed under `evaluation/results/` (`eval_dev_summary.csv`,
  `eval_dev_claims.csv`, `rq2_audit_dev.csv`) — they are mechanism evidence only,
  produced by `MockLLMClient`, and must be overwritten by the first real-LLM run.

---

## 4. Key design decisions (why things are the way they are)

- **Clean model is canonical** (macro-F1 0.908, not the leaked 0.998): a faithful
  explanation layer can't be built on timestamp-leaked decisions.
- **Two registers, not a gradient**: the detector's confidence is natively
  two-regime (empty middle); a finer scale would have no population.
- **Ambiguous pair asserts at pair level only** (`p_pair`, symmetric candidates,
  pcap disambiguation): the model knows "gafgyt tcp-or-udp", not which. Within-pair
  preference is a non-generalising capture artefact — forbidden by audit gate 3.
- **Freeze before tune**: KB/gold set frozen before retrieval work; case set frozen
  before prompt iteration. Prompt iteration happens on the **dev set only**.
  Verifiable in git — see §7 for the freeze tags and the ancestry checks that
  demonstrate each freeze preceded the work it constrains.
- **Judge from a different model family** than the generator (avoids the pipeline
  optimising the judge's scoring function).
- **Machine-verify what's mechanical** (feature/number claims), judge only what
  isn't (knowledge/procedural) — shrinks the judge's error surface.

---

## 5. Next steps

**Step 3 — real-LLM evaluation (blocked on keys).** Required env:

| Variable | Role |
|---|---|
| `OPENAI_API_KEY` | generator + self-check (default `gpt-4.1-mini`, temp 0) |
| `JUDGE_API_KEY` + `JUDGE_BASE_URL` + `JUDGE_MODEL` | judge — **different family** (e.g. Claude / Gemini) |

Order once keyed:
1. Dev-set smoke — first real model vs register rules + audit gates; failures seed
   the prompt-iteration log. Start at the cheapest useful size:
   `run_eval.py --split dev --limit 1 --configs full_rag` = **3 cases**, one per
   register path, ≈9 calls. `--limit`/`--configs` isolate their output under
   `results/scratch/` so a smoke can never overwrite committed results, and each
   run drops a `run_manifest_*.json` recording split/configs/models/versions.
2. Prompt iteration on the **dev set only** (bump prompt version, record
   failure-mode → measured-delta).
3. Frozen-set final 4-config runs → RQ1 taxonomy/hallucination table, RQ2 gate
   pass-rate table.
4. RQ3 — human scoring of 20 cases, Cohen's κ.

Cost estimate: frozen run ≈ 1000 `gpt-4.1-mini`-scale calls (cache dedupes by
`config|case|prompt_version`) — a few dollars.

**Deferred / backlog:**
- KB expansion to 300+ chunks with external material (MITRE ATT&CK, CVEs, vendor
  advisories) — README targets this; current KB is the self-authored core.
- Retrieval v2 improvements (only after end-to-end failure analysis): full-config
  `threat_assessment` regression (0.60→0.34), BM25 negative contribution.
- Evidence screen v2: per-class × per-feature univariate AUC table replacing the
  z-score/p99 proxy.
- Streamlit demo (detection → retrieval traces → report).

---

## 6. Environment & workflow notes

- **Use `.venv-wsl/`** (Python 3.14, gitignored) — the repo-root `.venv/` is a
  Windows venv (Py 3.9) and unusable from WSL. `.venv-wsl` has pandas/pyarrow/
  sklearn/xgboost/shap/chromadb/rank-bm25/sentence-transformers/torch; the two HF
  models are cached.
- **Run tests:** `.venv-wsl/bin/python -m pytest code/module2/tests -q` (78 tests,
  ~2 min; builds the ChromaDB index once).
- **Gitignored artifacts:** `retrieval/index/`, `generation/cache/`,
  `evaluation/judge_cache/`, `code/nbaiot_sampled.parquet`, `N-BaIoT/`.
- **Roles:** Claude = supervising architect (design, review, research writing);
  Codex (`codex_implement`) = delegated engineering. Note: codex-worker often
  reports false-positive `path_violations` on directory-glob matches / dirty tree —
  verify by reading the actual diff.

---

## 7. Version-control provenance (read before citing any commit)

**`main` is not the development history.** Before the repo was published to
GitHub, history was rebuilt as a single squashed commit (`7fd8b17 "Initial
commit"`) so that agent-configuration files (`CLAUDE.md`, `AGENTS.md`) would not
appear in the public repository. `main` therefore carries no record of the order
in which work was done.

The original 9-commit development history is preserved locally on the branch
**`history/pre-squash`** (head `9d45dca`), recovered from reflog on 2026-07-22.
It is intentionally **local-only and not pushed** — pushing it would republish
the agent-config files that the squash removed.

### Freeze tags (annotated, on `history/pre-squash`)

| Tag | Commit | Marks |
|---|---|---|
| `kb-v1.0.0` | `b22c326` | Module 2 KB + retrieval gold set frozen |
| `prompts-v1.0.0` | `33ee064` | Generation prompts + register rules frozen |
| `cases-v1.0.0` | `7267d27` | Module 3 evaluation case set frozen |

### Verifying "freeze before tune"

Each check exits 0, proving the freeze commit is an ancestor of — i.e. precedes —
the work it was supposed to constrain:

```bash
git merge-base --is-ancestor kb-v1.0.0      b0a6ba4   # KB frozen before retrieval layer
git merge-base --is-ancestor prompts-v1.0.0 bd041af   # prompts frozen before generation pipeline
git merge-base --is-ancestor cases-v1.0.0   afbabd5   # case set frozen before eval harness
```

Full development order: `8a9d74b` (baseline) → `b6c1c9a` (Module 2 skeleton) →
**`b22c326` (KB freeze)** → `b0a6ba4` (retrieval + ablation) → **`33ee064`
(prompt freeze)** → `bd041af` (generation pipeline) → **`7267d27` (case freeze)**
→ `afbabd5` (eval harness) → `9d45dca` (docs).

**Caveat for write-up:** these tags were applied on 2026-07-22, after the fact.
They are trustworthy as evidence of *ordering* — the commit DAG cannot be
back-dated without rewriting hashes — but they are not independent timestamped
pre-registration. Claim the ordering, not pre-registration.

**Do not run `git gc --prune=now`** without confirming `history/pre-squash` still
exists; the old chain has no other ref holding it.
