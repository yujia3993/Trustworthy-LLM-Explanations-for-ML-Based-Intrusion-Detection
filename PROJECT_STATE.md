# Project State

**Trustworthy LLM Explanations for ML-Based Intrusion Detection (N-BaIoT)**
Snapshot: 2026-07-24 · Branch `main` · 152 tests passing

This is the working-state document (progress, decisions, what's next). For the
research narrative and headline results see [README.md](README.md).

---

## 1. Status at a glance

| Module | Scope | State |
|---|---|---|
| **Module 1** | Two-stage detector + leakage audit + explainability exports | ✅ Complete, sealed (pre-existing) |
| **Module 2** | RAG explanation layer (KB, retrieval, generation) | ✅ Infrastructure complete |
| **Module 3** | Evaluation (case set, harness, metrics) | ✅ Complete — harness, 4-config dev ablation + 3 prompt-iteration rounds, **frozen 101-case run** (§11), **RQ3 human validation** (§12) |

**All three research questions are answered (2026-07-24).** The 101-case × 4-config frozen
evaluation ran to completion (generator `gpt-4.1-mini`, judge `claude-haiku-4-5-20251001`,
prompt v1.1.0, case set v1.0.0) — `n_fallback = 0` and `n_needs_review = 0` on all four
configs, manifest `partial: false`, zero retries over ~6 h and 404 (case, config) units —
and RQ3's human validation is scored. **§11 holds the reportable RQ1/RQ2 numbers, §12 the
RQ3 agreement.** Three results overturn or qualify earlier claims: the dev-set "all four
RQ2 gates pass" claim is retracted (§8.2 → §11.2); `naive_rag` matches the full retrieval
stack on every RQ1 metric (§11.1); and the judge's report-level rubric fails validation —
three of its four criteria are degenerate (§12.2). What remains is **write-up**, not
measurement.

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

**Measurement is finished.** RQ1/RQ2 come from the frozen run (§11); RQ3 is scored (§12).
No further API spend is required for the results as they stand.

**Immediate next action: the write-up.** The three headline claims and their caveats are
already stated in §11 and §12 and every number in them has been verified against the
committed CSVs. Points that must survive into the thesis, because each corrects or bounds
something a reader would otherwise assume:

1. §8.2's "all four RQ2 gates pass" is **retracted** — cite §11.2 instead, where
   `self_check`'s Round-1 fix lifting gate 4 to 0.990 is the real result.
2. `naive_rag` is not beaten by the full retrieval stack on any RQ1 metric (§11.1).
3. The grounding residual is **entailment-limited**, replicated on two independent axes
   (§9.3 across prompt versions, §11.3 across configs).
4. RQ3 validates the **claim-level** taxonomy only (κ=0.477, PABAK=0.668). The
   report-level rubric is **not** validated — three of four criteria are degenerate
   (§12.2). Disclose the single-rater limitation and the `case_id` stratum leak (§12.4).

**If a re-run ever becomes necessary** (protocol, rubric, or case-set change — each also
invalidates the caches), the environment is:

| Variable | Role |
|---|---|
| `OPENAI_API_KEY` | generator + claim extraction + self-check (`gpt-4.1-mini`, temp 0) |
| `JUDGE_API_KEY` + `JUDGE_BASE_URL` + `JUDGE_MODEL` | judge — **different family** |

**Deferred / backlog:**
- **Second RQ3 rater** — protocol §7 sought one and none was obtained. Without a
  human–human baseline, κ=0.477 cannot be attributed to judge unreliability rather than
  ordinary inter-human variation. This is the single highest-value addition to RQ3.
- **Report-level rubric v2** — the three degenerate criteria (§12.2) need either
  discriminating definitions or removal; as written they measure nothing.
- **Drop the stratum from `case_id` in rater-facing exports** (§12.4 confound).
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

> ⚠️ **This "all four gates at 100%" claim was later falsified by the frozen run.**
> This §8.2 baseline is `full_rag`, whose true gate-4 failure rate *on hedged_pair* is
> **25%** at n=101 (§11.2). Dev held only **4** hedged_pair cases, so a clean sweep has
> probability ≈ 0.75⁴ ≈ **1-in-3** — the observed 100% was luck, not a result. (The
> other configs fail hedged_pair gate 4 far harder: naive 44%, no_rag 86%, self_check
> 3%.) Do **not** cite "all four gates pass on real output." Cite the frozen numbers in
> §11.2, where the methodological result is instead that `self_check`'s Round-1 fix
> lifts gate 4 to **0.990** while the base retrieval configs sit at 0.84–0.91. The dev
> figure below is left as the historical iteration baseline, not a finding.

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

> **Independently replicated on the frozen set (§11.3).** This finding was derived on
> dev (n=14) by comparing *prompt versions*. The frozen run reproduces the same
> monotone relationship *across configs* (n=101): citation rate 0.15 → 0.50 → 0.61 →
> 0.67 across no_rag/naive/full/self_check, mis-attribution (cited-but-ubt / cited)
> climbing 0.00 → 0.03 → 0.06 → 0.08, and faithfulness flat at ~0.81 for all three
> retrieval configs. Two different axes (prompt version, config ladder), same
> conclusion — "cite more" buys compliance, not faithfulness.

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

---

## 11. Frozen 101-case 4-config results (2026-07-24) — the reportable numbers

Commits `9e6f122` (analysis script) + `7270005` (result CSVs). Generator `gpt-4.1-mini`,
judge `claude-haiku-4-5-20251001`, prompt v1.1.0, case set v1.0.0. Run integrity:
**`n_fallback = 0` and `n_needs_review = 0` on all four configs**, manifest
`partial: false`, **0 `LLM retry` lines** across 404 (case, config) units / ~6 h.
Artifacts: `evaluation/results/eval_frozen_{summary,claims}.csv`, `rq2_audit_frozen.csv`,
`run_manifest_frozen.json`, and the derived `claim_analysis_frozen{,_by_section}.csv`.

Unlike the dev tables in §9, these are **statistically reportable** (n=101, all 9
devices, all three registers, 3 known high-confidence errors). Where dev and frozen
disagree, **frozen is canonical** and the dev figure is an underpowered artifact.

### 11.1 RQ1 — taxonomy / hallucination

| config | claims | faithfulness | sup / ubt / false | halluc. rate | fabricated-num rate | factual (judge 1–5) |
|---|---|---|---|---|---|---|
| `no_rag` | 3363 | 0.422 | 1420 / 1914 / 29 | 0.0086 | 0.0000 | 3.87 |
| `naive_rag` | 3470 | **0.821** | 2849 / 594 / 27 | **0.0078** | 0.0105 | **4.80** |
| `full_rag` | 3618 | 0.812 | 2938 / 616 / **64** | 0.0177 | 0.0063 | 4.48 |
| `self_check` | 3641 | 0.815 | 2969 / 613 / 59 | 0.0162 | 0.0049 | 4.44 |

`invalid_refs` and `contextual_misuse` are 0 everywhere. **Central RQ1 read: retrieval is
the whole story, the elaborate stack is not.** `no_rag` → `naive_rag` nearly doubles
faithfulness (0.42 → 0.82); `naive_rag` → `full_rag` → `self_check` moves it **not at
all** (0.821 / 0.812 / 0.815). Worse, `full_rag` has **2.3× the hard hallucinations** of
`naive_rag` (64 vs 27 false claims) and a lower judge score (4.48 vs 4.80). On this task,
naive top-k RAG is the value; the reranker + query-decomposition stack does not earn its
complexity on any RQ1 metric. `self_check` halves nothing here (false 64→59) — its one
real win is RQ2 gate 4 (below).

The Round-2 scorer fix (§9.2) is **confirmed at scale**: feature-claim ubt collapses from
dev's 21/24/29/14 to frozen's 3/2/0/2, so the residual is now almost purely
knowledge/procedural, not a measurement artefact of unciteable alert-data numbers.

### 11.2 RQ2 — machine-checkable gate pass rates (this corrects §8.2)

| config | gate1 register↔margin | gate2 hedged disclosures | gate3 no within-pair order | gate4 prob. consistency | **all-gates** |
|---|---|---|---|---|---|
| `no_rag` | 1.000 | 0.970 | 1.000 | 0.693 | 0.693 |
| `naive_rag` | 1.000 | 1.000 | 1.000 | 0.842 | 0.842 |
| `full_rag` | 1.000 | 1.000 | 1.000 | 0.911 | 0.911 |
| `self_check` | 1.000 | 1.000 | 1.000 | **0.990** | **0.990** |

**Gate 4 does not hold at scale, and that is the actual finding.** All 57 failing
(case, config) pairs are on the **`hedged_pair`** register, all on gate 4 (three no_rag
cases also drop gate 2). Gates 1 and 3 are perfect; gate 2 is perfect except under
no_rag. So the machine-checkable story is not "everything passes" (§8.2, now retracted)
but: **register mapping and the no-within-pair-ordering rule are rock-solid, while
probability-string consistency on the ambiguous pair is the one hard gate — and
`self_check`'s Round-1 fix is what tames it** (0.990 vs the 0.84–0.91 base configs).
That is a *stronger* and more honest result: a named intervention measurably moves a gate
that the base pipeline fails ~9–16% of the time. Dev could not have shown this — it had 4
hedged_pair cases; frozen has 36.

### 11.3 RQ1 headline replicated: the residual is entailment-limited

`claim_analysis_frozen.csv` decomposes each config's ubt into feature / uncited-kp /
cited-but-ubt, and this reproduces §9.3's dev-only finding on an independent axis:

| config | kp citation rate | cited-but-ubt | mis-attribution (cited-but-ubt / cited) | faithfulness |
|---|---|---|---|---|
| `no_rag` | 0.15 | 0 | 0.000 | 0.422 |
| `naive_rag` | 0.50 | 42 | 0.031 | 0.821 |
| `full_rag` | 0.61 | 111 | 0.063 | 0.812 |
| `self_check` | 0.67 | 147 | 0.076 | 0.815 |

Citing more (0.15 → 0.67 across the ladder) **raises mis-attribution, not faithfulness** —
the judge increasingly rules the cited chunk does not entail the claim. §9.3 showed this
by varying the *prompt*; §11.3 shows it by varying the *config*. The unfaithfulness that
survives retrieval is **entailment-limited, not a citation-behaviour gap** — it bounds
what prompt engineering can promise and points the only real lever at retrieval precision.

### 11.4 Per-section faithfulness (feeds the retrieval failure analysis)

From `claim_analysis_frozen_by_section.csv`, faithfulness by report section:

| section | no_rag | naive | full | self_check |
|---|---|---|---|---|
| `attack_mechanism` | 0.206 | 0.781 | 0.788 | 0.806 |
| `confidence_notes` | 0.675 | 0.699 | **0.784** | 0.755 |
| `immediate_actions` | 0.009 | 0.843 | 0.852 | 0.806 |
| `longer_term_remediation` | 0.000 | **0.724** | 0.665 | 0.723 |
| `observable_indicators` | 0.977 | 0.983 | 0.939 | 0.945 |
| `threat_assessment` | 0.389 | 0.754 | 0.751 | 0.749 |

Note for the retrieval-v2 backlog item (§5): the full-config `threat_assessment`
**Recall@5 regression (0.60→0.34)** did **not** cost end-to-end faithfulness there
(0.751, level with naive's 0.754). full_rag's only section-level *loss* to naive is
`longer_term_remediation` (0.665 vs 0.724). Its only section-level *win* is
`confidence_notes` (0.784) — which is why gate 4 aside, full_rag buys almost nothing.
`observable_indicators` is near-ceiling for every config including no_rag (0.977) — it is
largely detector-data transcription, not knowledge that retrieval helps with.

---

## 12. RQ3 — judge validation against a human rater (2026-07-24)

Pipeline commits `9d45f74` (cache-backed export + κ scoring), `3683ce3` (grounding
material for the rater), `4fe0084`/`4d64345` (rater guide, committed before annotation),
`6db555e` (degeneracy flags). Artifacts: `results/rq3_scoring_sheet_{reports,claims}.csv`
(filled), `rq3_judge_reference.csv`, `rq3_case_materials.md`, `rq3_agreement.csv`.

Sample: 20 `full_rag` cases, seed-42 stratified — 12 `hedged_pair`, 6 `assertive_correct`,
2 `assertive_error` — and their 602 judge-routed claims. Validity precondition met: the
sheets were exported through the frozen run's caches, and all 602 claim texts were
verified byte-identical to `eval_frozen_claims.csv`, so both raters scored the same
material under the same rubric (`prompts/judge.md`, quoted verbatim in
`rq3_rater_guide.md`).

| metric | κ | raw | n | interpretable? |
|---|---|---|---|---|
| **claim_labels** (primary) | **0.477** | 83.4% | 602 | ✅ |
| factual_accuracy | 0.044 | 70.0% | 20 | ❌ scale mismatch (§12.3) |
| actionability_device_specific | 0.000 | 70.0% | 20 | ❌ degenerate (§12.2) |
| actionability_phases_separated | 1.000 | 100% | 20 | ❌ degenerate (§12.2) |
| actionability_matches_category | 1.000 | 100% | 20 | ❌ degenerate (§12.2) |

### 12.1 Primary result — claim-label agreement

κ = **0.477** ("moderate", Landis–Koch) on raw agreement of **83.4%** (502/602).

| human ↓ / judge → | supported | ubt | false | **total** |
|---|---|---|---|---|
| supported | **441** | 61 | 1 | 503 |
| unsupported_but_true | 19 | **60** | 1 | 80 |
| unsupported_and_false | 11 | 7 | **1** | 19 |
| **total** | 471 | 128 | 3 | 602 |

The gap between 83.4% raw and κ=0.477 is the **κ paradox**: both raters put ~80% of claims
in `supported`, which inflates the chance-agreement term and deflates κ. Report both, plus
**PABAK = 2·P₀ − 1 = 0.668**, which is the standard prevalence-adjusted companion.

Two asymmetries are substantive, not noise:

- **The human is more lenient about entailment.** 61 claims scored `supported` by the human
  were `unsupported_but_true` to the judge, against 19 the other way. The judge holds a
  stricter entailment bar than a human reading the same chunk.
- **The human calls falsehood far more often** — 19 vs the judge's 3. Of the human's 19,
  the judge scored 11 `supported` and 7 `unsupported_but_true`, agreeing on exactly **one**.
  Given RQ1 reports `unsupported_and_false` as the hallucination rate, this is a direct
  caution: **the judge's hallucination counts are likely a floor, not an estimate.**

By stratum, agreement is *best* where the task is hardest:

| stratum | n | raw | κ |
|---|---|---|---|
| `hedged_pair` | 399 | 90.0% | **0.601** |
| `assertive_correct` | 152 | 71.1% | 0.333 |
| `assertive_error` | 51 | 68.6% | 0.268 |

The register rules constrain hedged-pair reports tightly, and both raters track those
constraints well. Excluding `assertive_error` entirely, κ = 0.505 (n=551) — close to the
headline, so the confound in §12.4 does not drive the primary result.

### 12.2 Three report-level criteria are degenerate — and that is itself the finding

κ is undefined when either rater is constant, because the chance-correction term collapses;
`metrics.py` then returns 1.0 or 0.0 from a degenerate branch. That fired three times:

- `actionability_phases_separated` and `actionability_matches_category`: **both raters
  scored 1 on all 20 cases.** 100% raw agreement, but κ=1.0000 is the degenerate branch,
  **not** evidence of judge validity.
- `actionability_device_specific`: the **judge scored 1 on all 20**; the human scored 0 on
  six. 70% raw agreement, but κ=0.0000 is the degenerate branch, not chance-level agreement.

This is systemic, not a small-sample accident. Across all 404 frozen units the judge's
`actionability_phases_separated` mean is **exactly 1.000** — it never once assigned 0 —
and `matches_category` is 1.000 for three of four configs (0.990 for `no_rag`);
`device_specific` runs 0.931–1.000.

**So three of the four report-level criteria have no discriminative power as the judge
applies them.** They are near-constant by construction, so they can neither be validated
against a human nor carry information in RQ1/RQ2. This is a defect of the rubric's
report-level half, and the honest conclusion is that only the claim-level taxonomy earned
its keep. `rq3_agreement.csv` now carries `raw_agreement`, `n_distinct_human`,
`n_distinct_judge` and a `degenerate` flag so the number cannot be misread (`6db555e`).

### 12.3 `factual_accuracy` is not interpretable here

The rater used only **{1, 5}** (18 fives, 2 ones); the judge used **{2, 4, 5}**. Raw
agreement 70%, κ = 0.044. Excluding the two `assertive_error` cases the human is constant
at 5, so κ is undefined outright.

`rq3_rater_guide.md` §4.3 predicted this failure mode and instructed the full 1–5 range
precisely to avoid it; the rater nonetheless scored on an effective two-point scale. Since
the judge places 39.8% of its scores on the unanchored 4 and 2, a two-point rater cannot
match a third of the items regardless of judgement quality. The coefficient is reported as
measured, flagged as uninterpretable, and **not** re-collected — see §12.5.

### 12.4 The `assertive_error` disagreement, and its confound

**Both reports the human scored 1** (errors that would misdirect the response) are the two
`assertive_error` cases — the stratum where the classifier is confidently *wrong*
(`y_pred != label_type`, margin ≥ 0.9; here p_top1 = 0.9992). The judge scored them **4 and
5**.

The mechanism is structural: **the judge has no ground-truth access.** It evaluates a
report against ALERT DATA that already asserts the wrong class at p=0.9992. A report that
faithfully renders that input contains no false statement *relative to its inputs*, so the
judge cannot detect the misclassification even in principle. The human, holding the truth,
sees a report that would send an analyst after the wrong attack.

⚠️ **Confound — disclose this, do not build on it.** The sheets key on `case_id`, and the
case_id string literally contains `assertive_error`. **The rater was therefore not blind to
the stratum**, and these two scores may reflect knowing the label rather than detecting the
error from the report. The correct reading is *two raters with unequal information*, not
*the human caught what the judge missed*. This is a design defect in the sheet export
(the case_id was carried through as the alignment key without considering what it encodes),
and it is the reason the §12.1 sensitivity check excluding `assertive_error` matters.

The judge-side limitation stands on its own regardless of the confound: **an LLM judge
scoring a report against the detector's own output cannot audit the detector.** Faithfulness
to a wrong input is indistinguishable from correctness. Any pipeline relying on such a judge
for factual accuracy inherits that blind spot.

### 12.5 What was deliberately not done, and limitations

- **No re-annotation.** By the time the scale-usage problem in §12.3 was visible, the rater
  had seen the coefficients. Re-scoring afterwards would fit the human to the judge and
  destroy exactly what RQ3 measures. The result stands as collected.
- **Single rater**, per `eval_protocol.md` §7; a second was sought and not obtained. With
  n=20 report-level and one rater there is no human–human baseline to contextualise
  κ=0.477, so it cannot be said whether that is judge unreliability or ordinary inter-human
  variation on a hard task.
- **Prior exposure**: the rater had seen the judge's *aggregate* `factual_accuracy` mean
  (4.48, §11.1) before scoring. Aggregate only, and κ is chance-corrected against marginals,
  so it cannot manufacture per-item agreement — recorded for completeness.
- **n=20 / n=602** with wide confidence intervals, fixed in advance by protocol §7.
- The 4 and 2 points of `factual_accuracy` are unanchored in the frozen rubric; judge and
  human interpolated them independently (`rq3_rater_guide.md` §4).

**Net read for the write-up:** the claim-level three-way taxonomy is validated at moderate
agreement (κ=0.477, PABAK=0.668, 83.4% raw), with the judge stricter on entailment and
markedly more conservative about declaring falsehood. The report-level rubric is not
validated — three of four criteria are degenerate and the fourth is uninterpretable through
rater scale usage. Two independent judge limitations are established: hallucination counts
are a floor, and a judge scored against the detector's own output cannot audit the detector.
