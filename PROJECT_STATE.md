# Project State

**Trustworthy LLM Explanations for ML-Based Intrusion Detection (N-BaIoT)**
Snapshot: 2026-07-23 · Branch `main` · 126 tests passing

This is the working-state document (progress, decisions, what's next). For the
research narrative and headline results see [README.md](README.md).

---

## 1. Status at a glance

| Module | Scope | State |
|---|---|---|
| **Module 1** | Two-stage detector + leakage audit + explainability exports | ✅ Complete, sealed (pre-existing) |
| **Module 2** | RAG explanation layer (KB, retrieval, generation) | ✅ Infrastructure complete |
| **Module 3** | Evaluation (case set, harness, metrics) | ✅ Harness complete; ✅ 4-config dev ablation + 3 prompt-iteration rounds done; ✅ frozen pre-flight smoke green; ⏳ frozen runs + RQ3 pending |

**Prompt-iteration phase complete (2026-07-23).** The 4-config dev ablation ran on
real models (generator `gpt-4.1-mini`, judge `claude-haiku-4-5-20251001`), followed
by three dev-only prompt-iteration rounds — two kept, one reverted after failing its
pre-registered decision gate (see §9). A frozen-split **pre-flight smoke** then
validated the frozen path end-to-end at the current prompt state (§9.4), and the
harness was hardened for a multi-hour unattended run (§10). **Next concrete step:
the frozen 101-case 4-config runs** (≈$7.2, see §5 for the two-vendor split) →
RQ1/RQ2 tables, then RQ3 human
scoring + κ.

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
  numbers, invalid [E#]/[C#] refs, contextual misuse). An earlier "zero false
  positives" claim here was **falsified by the first real run** and has been
  corrected — see §8.3. The verifier now also accepts the exact decimal expansion
  of scientific-notation evidence values; no numeric tolerance was introduced.
- `claims.py` (extractor + mock), `judge.py` (env-separate judge client + cache +
  mock), `metrics.py` (taxonomy aggregation + Cohen's/weighted κ),
  `run_eval.py` (4-config orchestrator → summary/claims/RQ2 CSVs),
  `rq3_sheet.py` (20-case human scoring sheet).
- The committed CSVs under `evaluation/results/` (`eval_dev_summary.csv`,
  `eval_dev_claims.csv`, `rq2_audit_dev.csv`) now hold the **real 4-config dev
  ablation** output (2026-07-23), replacing the earlier `MockLLMClient` placeholders.
  Caveat: they carry the **v1.0.0** labels — the Round-2 scorer fix (§9.2) is not
  re-scored into them; the deterministic re-score in §9.2 documents that delta.

### Caching architecture (load-bearing for cost — added 2026-07-22)

Three independent on-disk caches, all gitignored. Each key is content-addressed so
that changing an input invalidates only what depends on it:

| Cache | Key material |
|---|---|
| `generation/cache/` | config · case_id · prompt_version · **generator model** |
| `evaluation/claim_cache/` | **extractor model** · sha256(claim prompt) · sha256(report) |
| `evaluation/judge_cache/` | judge model · case_id · config · eval_prompt_version · sha256(report) · **sha256(ordered claims)** |

This is what makes iteration affordable: after the fabricated-number fix, the entire
14-case dev evaluation was **re-run with zero API calls in 1m54s** (versus 10m14s and
~$0.25 for the uncached run). Without it, every metric-definition change would cost a
full re-run — ~$7.2 at frozen-set scale.

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

**Immediate next action: the frozen 101-case 4-config runs.** Prompt iteration is
finished (§9); the dev set has served its purpose. The reportable numbers come from
the frozen set, at the current prompt state (v1.1.0: Round-1 self_check fix + Round-2
scorer fix; Round 3 reverted).

```bash
set -a; source ~/.config/llm-keys.env; set +a     # keys are NOT auto-loaded
cd code && nohup ../.venv-wsl/bin/python -m module2.evaluation.run_eval \
  --split frozen > ../frozen_run.log 2>&1 &
```

**≈$7.2, ~4–6 h**, split **~$2.9 OpenAI / ~$4.3 Anthropic** — measured from the cached
prompts and responses of the §9.4 smoke, not estimated. The judge is the expensive half
despite moving fewer tokens (0.46 MTok out vs 1.26): it echoes every claim verbatim and
Haiku bills output at 5×. **Check both balances, not just OpenAI.** Progress goes to
stderr, one line per
(case, config) with an ETA — hence `2>&1` into the log. **Always verify
`n_fallback == 0` and that all three `JUDGE_*` vars are set** (§8.1 traps) before
believing the numbers; also check the log for `LLM retry` bursts (§10). Then:

1. RQ1 taxonomy/hallucination table + RQ2 gate pass-rate table from the frozen output.
2. RQ3 — human scoring of 20 cases, Cohen's κ (`rq3_sheet.py`).

A standalone dev-baseline refresh at v1.1.0 is **not** worth ≈$0.65: for the
non-`self_check` configs the reports are near-identical to v1.0.0, and the frozen run
is the canonical artifact. The committed dev CSVs stay the v1.0.0 iteration baseline.

**Environment required for any real run** (see §8.1 for storage and traps):

| Variable | Role |
|---|---|
| `OPENAI_API_KEY` | generator + claim extraction + self-check (`gpt-4.1-mini`, temp 0) |
| `JUDGE_API_KEY` + `JUDGE_BASE_URL` + `JUDGE_MODEL` | judge — **different family** |

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
- **Run tests:** `.venv-wsl/bin/python -m pytest code/module2/tests -q` (126 tests,
  ~4.5 min; builds the ChromaDB index once via the session fixture in `tests/conftest.py`).
- **Memory is the binding resource, not cores** (8 cores / 7 GB). A test run loads
  ChromaDB + both HF models; so does a real eval run. Two of those concurrently is
  already tight — do not run a codex test suite alongside the frozen eval.
- **Gitignored artifacts:** `retrieval/index/`, `generation/cache/`,
  `evaluation/claim_cache/`, `evaluation/judge_cache/`,
  `evaluation/results/scratch/`, `code/nbaiot_sampled.parquet`, `N-BaIoT/`.
- **Roles:** Claude = supervising architect (design, review, research writing);
  Codex (`codex_implement`) = delegated engineering. Note: codex-worker often
  reports false-positive `path_violations` on directory-glob matches / dirty tree —
  verify by reading the actual diff.
- **Codex worktrees now live OUTSIDE the repo** (`CODEX_WORKER_WORKTREE_DIR=
  ~/.codex-worktrees` in the gitignored `.mcp.json`; takes effect on MCP-server
  restart). They used to be created at `.codex-worker/worktrees/<id>/`, which is a
  *real nested git repository* inside the workspace: VS Code auto-detects it as a
  second Source Control provider (hence a busy SCM badge with nothing Modified in the
  main repo, since `.codex-worker/` is gitignored), and it leaves a full second copy
  of the tree for `find`/`grep`/bare `pytest` to trip over. All cache and index paths
  resolve from `__file__`, so a worktree test run cannot touch the main tree's caches.
- **`codex_implement` defaults to a 600 s timeout** (`CODEX_WORKER_TIMEOUT`), which is
  barely twice the test suite's runtime — pass `timeout_seconds` explicitly on any
  task whose acceptance criteria include running the full suite.
- **Commit before every `codex_implement` call.** `base_ref` defaults to `HEAD`, so
  an isolated worktree branches from the last commit and cannot see uncommitted work.
  This bit twice on 2026-07-22; the second time was nearly invisible — the worktree's
  `test_evaluation.py` had dropped 5 test functions from the uncommitted round and
  added 5 of its own, so both files had 19 test functions and the suite was green
  either way. A blind `cp` would have silently deleted a whole round of fixes.
  If delegating with a dirty tree is unavoidable, diff the symbol inventory
  (`comm -23 <(grep '^def test_' a | sort) <(grep '^def test_' b | sort)`) and
  hand-apply only the new delta. Checking the reported test count against the main
  tree's current count catches divergence early.

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

---

## 8. First real-LLM evaluation (2026-07-22)

### 8.1 Model configuration

| Role | Model | Endpoint |
|---|---|---|
| Generator / claim extraction / self-check | `gpt-4.1-mini` | api.openai.com |
| Judge | `claude-haiku-4-5-20251001` | `https://api.anthropic.com/v1` (OpenAI-compatible) |

Independence holds: different families, verified at runtime through the project's own
client, not just by `curl`.

Keys live in **`~/.config/llm-keys.env`** (outside the repo, chmod 600, **not**
auto-loaded — every real run must `source` it). The project reads `os.environ`
directly; there is no dotenv support, so a repo-local `.env` would be silently
ignored *and* is not gitignored.

**Two traps worth re-reading before any run:**

1. `JUDGE_MODEL` defaults to `gpt-4.1-mini` if unset — the judge silently becomes the
   same model as the generator and RQ3 independence is destroyed with no error. All
   three `JUDGE_*` variables must be set together.
2. Generation **silently falls back** to a template report on any
   `LLMUnavailableError` (bad key, no credit, network) — the run completes and writes
   normal-looking CSVs. **Always check `n_fallback == 0`** before believing any real
   numbers.

### 8.2 Dev baseline — `full_rag`, 14 cases, 483 claims

Artifacts: `results/scratch/{eval_dev_summary,eval_dev_claims,rq2_audit_dev}__full_rag.csv`
plus `run_manifest_dev__full_rag.json` (records split, configs, both model IDs, and
all three version strings).

| | |
|---|---|
| **All four RQ2 gates** | **100%** (gate1 register↔margin, gate2 hedged disclosures, gate3 no within-pair ordering, gate4 probability consistency) |
| `n_fallback` / `n_needs_review` | 0 / 0 |
| faithfulness | 0.7992 |
| supported / unsupported_but_true / unsupported_and_false | 386 / **90** / 7 |
| hallucination_rate | 0.0145 |
| fabricated numbers | **1 of 288** numeric tokens |
| invalid refs / contextual misuse | 0 / 0 |
| factual_accuracy (judge, 1–5) | 4.43 |

**All four machine-checkable RQ2 gates passing on real model output across all three
register paths is the central methodological result so far** — until now they had only
mock evidence.

The single genuine fabrication is worth quoting, since it is exactly what the checker
exists to catch:

> `assertive_correct-15007`: "This calibration reflects a long-run error rate of
> **0.005%** in this high-confidence regime"

An invented calibration statistic that appears nowhere in the case data.

**Largest open defect:** `unsupported_but_true` = 90/483 = **18.6%**, stable between
the 3-case smoke (19%) and the 14-case run — systematic, not noise. The model asserts
true things without citing evidence. See §5 for why the ablation must come first.

### 8.3 Four defects that only real models exposed

Every one of these was invisible under `MockLLMClient`. Recorded because they are the
strongest argument for smoke-testing before spending a frozen-set budget.

1. **Judge responses arrive fenced.** Anthropic's OpenAI-compatible endpoint wrapped
   the JSON in ```` ```json ```` in **14/14** cases; `json.loads` has zero tolerance.
   Fixed by stripping a fence only when the entire response is one fenced block —
   prose-wrapped JSON still fails loudly rather than degrading to lenient parsing.
2. **Generation caching was dead code.** `generate_report` had a complete cache
   implementation gated on `if cache is not None`, but `run_eval` never constructed a
   `ReportCache` — so `--no-cache` only ever controlled the judge, and every rerun
   re-paid full generation cost. The cache key also lacked the model name, so mock and
   real runs could have collided.
3. **Judge cache was keyed on the report but not the claims.** The judge's output is a
   function of *(report, claims)*, yet the key covered only the report — while claim
   extraction had no cache at all and is **not deterministic** (the same byte-identical
   cached report yielded 34 claims on one run and 35 on the next; `temperature=0` is
   not a determinism guarantee and no seed is set). A rerun therefore hit a cached
   judge result whose label count no longer matched and crashed. Fixed by caching
   extraction (which also makes runs reproducible) *and* adding an ordered-claims
   digest to the judge key.
4. **`feature_verify` false-positived on scientific notation.** Evidence values ≥ 1e4
   are rendered `%.4g`, so the prompt shows `5.797e+04`; the model faithfully expands
   it to `57,970` and was flagged as fabricating. This was **systematic**, not
   incidental, and it inflated a headline RQ1 metric: `fabricated_number_rate` read
   0.0104 when the true value was 0.0035 (3 flags, of which 2 were false). Fixed by
   allowing the exact decimal expansion of the same rounded value via
   `decimal.Decimal`. **No numeric tolerance was added** — `57971`, `57969` and `5797`
   are all still flagged, and there is a test asserting the allowed set's exact
   contents so no spurious entries can creep in.

Note that `57969` — the correct rounding of the *raw* value 57969.3 — is still
rejected, and rightly so: the prompt showed `5.797e+04`, so `57,970` is the only
faithful transcription. The model writing `57,970` rather than `57,969` is itself
evidence that it transcribed the prompt rather than inventing a number.

### 8.4 Reproducibility caveat for the write-up

Claim extraction is not deterministic across runs (see §8.3 item 3). The
`ClaimCache` freezes claims to disk, so **a given set of results is reproducible from
the cache**, but a from-scratch re-extraction may yield a slightly different claim
count. This must be disclosed rather than claimed away; setting a seed is not
available on the endpoint in use.

---

## 9. 4-config dev ablation + prompt iteration (2026-07-23)

All numbers below are **dev set, n=14** — directional, not statistical. At this scale
run-to-run non-determinism swings judge-scored metrics by ~±2 claims / ~±0.3 factual
(measured in Round 1). Only the machine-checkable gates and the deterministic scorer
are resolvable on dev; the reportable RQ1/RQ2 tables come from the frozen 101-case run.

### 9.1 The 4-config dev ablation (prompt v1.0.0, `n_fallback = 0` all configs)

| config | faithfulness | supported / ubt / false | RQ2 all-gates | factual |
|---|---|---|---|---|
| `no_rag` | 0.368 | 167 / 287 / 0 | 0.786 | 4.00 |
| `naive_rag` | 0.794 | 362 / 90 / 4 | 0.929 | 4.71 |
| `full_rag` | 0.799 | 386 / 90 / 7 | 1.000 | 4.43 |
| `self_check` | 0.808 | 388 / 89 / 3 | 0.929 | 4.79 |

**Central read — `unsupported_but_true` is a RESIDUAL of RAG, not caused by it.**
`no_rag` sits at 63.2% ubt; adding retrieval collapses it to ~19%, and the elaborate
stack (`full_rag`) adds only ~1pt of ubt reduction over naive top-k. Retrieval is the
cure; the sophisticated interventions show diminishing, mixed returns (`full_rag` has
*more* false claims than `naive_rag`). `self_check` halves hard hallucinations
(false 7→3) and tops factual accuracy but is the only config that generates twice.
Committed CSVs (`evaluation/results/eval_dev_*.csv`) hold this v1.0.0 output.

### 9.2 Prompt-iteration rounds (dev only, freeze-before-tune preserved)

Each round: one bounded change, measured delta, keep-or-revert. Two kept, one reverted.

- **Round 1 — kept (prompt v1.0.0 → v1.1.0).** The ablation showed `self_check` failing
  RQ2 gate4 on `hedged_pair-105008`: the self-check *rewrite* made the register-mandated
  "within-pair split has no evidential value" sentence concrete by quoting the split
  values (`p_top1=0.4998, p_top2=0.4993`), which the hedged_pair register forbids
  surfacing at all (base generation never did). Fix in `self_check.md` Task 3: a
  source-matching number the REGISTER RULES forbid must still be removed. Result:
  `self_check` gate4 / all-gates **0.929 → 1.000**, faithfulness/ubt stable.

- **Round 2 — kept (harness fix, no prompt/version change).** Decomposing `full_rag`'s
  90 ubt: **21 feature (alert-data) + 60 uncited knowledge/procedural + 9 cited-but-ubt**.
  The 21 are a *measurement artifact*: ALERT DATA (`p_top1/p_pair/margin/entropy`) is
  rendered with no citable `[E#]/[C#]` token, so register-mandated probability claims
  are structurally unciteable — yet `classify_feature_claim` sent every uncited number
  to ubt, contradicting protocol §1 ("…material (or ALERT DATA)"). Fix in
  `feature_verify.py`: an *uncited* feature claim whose numbers are all correct
  ALERT-DATA numbers is `supported` (evidence values still need `[E#]`; fabrications
  still false). `eval_protocol.md` §3 reconciled to §1 (dated note, no
  `eval_prompt_version` bump — matching the scientific-notation precedent). Deterministic
  re-score of the committed dev claims (same reports, both scorings), faithfulness:

  | config | before | after | feature ubt flipped |
  |---|---|---|---|
  | `no_rag` | 0.368 | 0.432 | 29 |
  | `naive_rag` | 0.794 | 0.844 | 23 |
  | `full_rag` | 0.799 | 0.841 | 20 of 21 |
  | `self_check` | 0.808 | 0.838 | 14 |

  (`full_rag`'s 1 held-back claim is a no-number "maximum confidence" paraphrase,
  correctly left ubt by the ≥1-alert-data-number guard.)

- **Round 3 — REVERTED (attempted prompt v1.1.0 → v1.2.0, then reverted).** Targeted the
  60 uncited knowledge/procedural ubt. A deterministic diagnosis first (replay
  `full_rag`'s provided context; rank every KB chunk by dense sim to each claim) found
  the residual is **generation-behaviour, not retrieval**: retrieval-missed was the
  *smallest* bucket at every threshold; ~11% are classifier-calibration meta-claims the
  KB can never ground. Change: `system.md` GROUNDING RULE 1 → "when a provided CONTEXT
  excerpt supports a claim you MUST cite it". Full 4-config dev run (suffixed output to
  protect the decision gate). **It failed its target and tripped the guards, so it was
  reverted:** knowledge/proc ubt did not drop (`full_rag` 69→74, `self_check` 75→87);
  `full_rag` all-gates 1.000→0.929; `self_check` false 3→14.

### 9.3 The headline finding — the grounding residual is entailment-limited

Round 3 is a *productive* negative result. The model **obeyed** the citation mandate —
`full_rag` knowledge/procedural citation rate rose **0.59 → 0.67** — but faithfulness
did **not** follow: supported stayed flat and cited-but-ubt rose 9 → 13. The extra
citations were **mis-attributed** (the judge ruled the cited chunk does not entail the
claim). This cleanly separates two hypotheses: *"the model won't cite its context"*
(**false**) vs *"the provided context is topically related but does not precisely
entail the specific claims"* (**true**). **The residual unfaithfulness is
retrieval-entailment-limited, not a prompt-fixable citation-behaviour gap** — "cite
more" raises compliance without raising faithfulness. This is a stronger RQ1 statement
than any marginal prompt win, and it bounds what prompt engineering can promise on this
task. Improving it would require more precise retrieval or is an irreducible reliance
on parametric knowledge (plus the ~11% calibration meta-claims no KB chunk can ground).

### 9.4 Frozen pre-flight smoke (2026-07-23, `--limit 1`)

Ran **after** the §9 documentation was committed (`93cf638`), which is why it appears
here rather than above. Artifacts: `results/scratch/*_frozen__limit1.*`.

`--split frozen --limit 1` takes one case per stratum — **4 cases × 4 configs = 16
generations**, at prompt v1.1.0, case set v1.0.0, `n_fallback = 0 / n_needs_review = 0`.

| config | faithfulness | supported / ubt / false | all-gates | factual |
|---|---|---|---|---|
| `no_rag` | 0.429 | 57 / 76 / 0 | 0.750 | 4.00 |
| `naive_rag` | 0.884 | 129 / 16 / 1 | 1.000 | 4.25 |
| `full_rag` | 0.860 | 123 / 18 / 2 | 1.000 | 4.50 |
| `self_check` | 0.818 | 126 / 28 / 0 | 1.000 | 5.00 |

Two things this buys, neither available from the dev set:

1. **`assertive_error` met a real model for the first time** (`assertive_error-317103`)
   — the stratum that cannot appear in dev, since all 3 known high-confidence errors
   are in the frozen set. It passed all four gates in all four configs.
2. The **frozen** case set, at the **current** prompt state, produces parseable judge
   output and zero fallbacks — the two failure modes that historically only surfaced
   against real endpoints (§8.3).

`no_rag` fails gate2 + gate4 on `hedged_pair-100000`: without retrieval the model drops
the mandated hedged disclosures and mis-states a probability. That is the ablation floor
behaving as designed, not a regression.

**Do not compare these numbers to the §9.1 table** — this run scores with the Round-2
fix (§9.2), the committed dev CSVs do not. Compare against §9.2's re-scored column.

---

## 10. Run hardening for the unattended frozen run (2026-07-23)

Commit `41ce10b`. Two defects that only matter at frozen scale: a full run is ~1300
sequential API calls over 4–6 hours, and there was **no retry anywhere**.

- **Retry.** All network I/O funnels through `OpenAICompatibleClient.complete`, which
  the judge and the claim extractor both delegate to, so one implementation covers
  generation, self-check, extraction and judging. Transient `{429,500,502,503,504}` and
  network/timeout errors now get bounded exponential backoff with full jitter (default
  3 retries, 30 s ceiling), honoring a numeric `Retry-After`. 4xx and malformed
  responses still fail on the first attempt so a bad key or model surfaces immediately.
  After exhaustion the same `LLMUnavailableError` is raised, so the template-fallback
  path and the `n_fallback` metric are unchanged. Sleep is injectable — the 8 new tests
  run in 0.13 s with no real network and no wall-clock.
- **Progress.** `run_eval` prints one line per (case, config) to **stderr** — index/total,
  cache-hit flag, unit elapsed, total elapsed, ETA. stdout stays reserved for the summary
  table. `--no-progress` disables it.

**Operational note:** OpenAI returns **429 for quota exhaustion**, not just rate limits,
so a run that goes dry retries 3× per call before failing. Claim extraction has no
fallback path, so the run will die loudly rather than silently produce template reports
— the caches keep everything already completed. If the log starts filling with
`LLM retry` lines, kill it and top up rather than letting it grind through the remainder.

Why it was safe to do this before the frozen run: nothing here touches a prompt, the
protocol, the case set, any version string, or any cache key. `max_retries=0` reproduces
the previous behaviour exactly, and a test pins that.
