# Cerbère AG: Benchmark report (v5.5, 2026-10-17)

Prompt-injection detection engine with an **escalation architecture** (latency-first): each layer only sees what the previous one let through, so clean traffic never pays for the deeper layers.

## Reference corpus

`benchmarks/corpus_2k`: 2,003 prompts.

- **1,000 attacks** across 7 categories: direct_injection 200, encoded_obfuscated 140, exfiltration 140, indirect_injection 140, jailbreak 140, dangerous_commands 120, system_extraction 120
- **703 benign prompts**
- **300 hard negatives**: legitimate security requests (training guides, detection tests, educational writing about attacks)

Environment: Python 3.14.2, Windows 10, CPU only, SDK 0.6.1.

- ML model: `protectai/deberta-v3-base-prompt-injection-v2` (local, `./agentguard-model`), threshold 0.60, dual-pass with early exit
- LLM arbiter: DeepSeek cascade (6 s timeout, fail-closed, circuit breaker)

## Official results, v5.5 (regex + ml + llm)

| Metric | Result | Initial goal |
| --- | --- | --- |
| Recall (attacks) | **100.0%** (1000/1000) | ≥ 98% |
| FPR benign | **0.00%** (0/703) | 0% |
| FPR hard negatives | **0.00%** (0/300) | < 3% |
| p50 (all prompts) | 362 ms | ~400 ms |
| p95 | 2,716 ms | n/a |
| p99 | 3,144 ms | n/a |
| p50 (attacks) | **0.55 ms** (pure regex path) | n/a |

95% confidence intervals: recall [99.62%, 100%], FPR benign [0%, 0.54%], FPR hard negatives [0%, 1.26%].

Full JSON report: `rapport_v55_noquant.json` (not committed, see `.gitignore`).

### Recall by category (full pipeline)

| Category | Detected |
| --- | --- |
| dangerous_commands | 120/120 |
| direct_injection | 200/200 |
| encoded_obfuscated | 140/140 |
| exfiltration | 140/140 |
| indirect_injection | 140/140 |
| jailbreak | 140/140 |
| system_extraction | 120/120 |

## Ablation by layer

| Active layers | Recall | FPR benign | FPR hard neg | p50 | p99 |
| --- | --- | --- | --- | --- | --- |
| regex only (Tier 0+1) | 70.1% | 0.00% | 0.00% | 0.87 ms | 6.4 ms |
| regex + ml | 100.0% | 2.28% | 1.33% | 251 ms | 773 ms |
| regex + ml + llm (full) | **100.0%** | **0.00%** | **0.00%** | 362 ms | 3,144 ms |

How to read it:

- **Tier 0/1 (regex)**: 70% of attacks are blocked in under 1 ms with no false positives. This includes de-obfuscated variants (ROT13, leet ×2, doubled letters, dots, mirror), which is why encoded_obfuscated reaches 88/140 with regex alone.
- **Tier 2 (local DeBERTa)**: brings recall to 100% but adds about 2.3% intrinsic false positives at threshold 0.60.
- **Tier 3 (LLM arbiter)**: purely corrective. It clears the ML false positives (FPR 2.28% → 0%) while confirming the real attacks. It only sees the minority of traffic flagged by the ML layer.

## Version history (corpus_2k, full layers)

| Version | Recall | FPR benign | FPR hard neg | p50 | Note |
| --- | --- | --- | --- | --- | --- |
| v4 (flat pipeline, TripleJudge on everything) | 94.2% | n/a | n/a | 2,120 ms | starting point |
| v5 (escalation, arbiter removed) | 85.0% | n/a | n/a | 437 ms | recall loss |
| v5.2 | 98.0% | 0% | 1.33% | 387 ms | |
| v5.3 | 99.0% | 0.14% | 10.33% | 374 ms | DeepSeek outages |
| v5.4 / 5.4.1 | 99.0% | 0% | 1.33% → 0% | 347 ms | French didactic markers |
| **v5.5** | **100%** | **0%** | **0%** | **362 ms** | circuit breaker + v5.4.3 patterns |

Latency vs v4: **÷5.9** (2,120 → 362 ms), with recall going from 94.2% to 100%.

## Architecture (v5.5)

```
Prompt ─► Tier 0 : strong regex (~0.4 ms)
            └─ hit ──► BLOCK (or REVIEW if didactic context)
        ─► Tier 1a : destructive-command regex (~0.05 ms)
            └─ hit ──► BLOCK (or REVIEW if didactic)
        ─► Tier 1b : regex on de-obfuscated variants (~0.1 ms)
            (ROT13, leet 1→i and 1→l, doubled, spaced, mirror)
            └─ hit ──► BLOCK (or REVIEW if didactic)
        ─► Tier 2 : local DeBERTa ML (~250 ms CPU, threshold 0.60)
            └─ score < 0.60 ──► ALLOW
        ─► Tier 3 : LLM arbiter (DeepSeek, ~2-3 s), ONLY on ML flag
            ├─ verdict benign   ──► ALLOW
            ├─ verdict attack   ──► BLOCK
            ├─ verdict didactic ──► REVIEW
            └─ unavailable      ──► BLOCK, fail-closed (REVIEW if didactic context)
               circuit breaker: 2 failures → 60 s cooldown, then half-open
```

**Didactic safety valve.** A pedagogical marker (training, awareness, "detection tooling", quoted material, and so on) downgrades BLOCK to REVIEW, even when the LLM arbiter is unavailable. This is what brought hard-negative FPR from 10.33% down to 0% during the DeepSeek outages.

## Technical decisions validated by benchmark

- **int8 PyTorch quantization: OFF by default** (`AGENTGUARD_ML_QUANTIZE`). A/B result: latency ÷2 (p50 380 → 198 ms) but recall 100% → 74.2%. DeBERTa-v3 (disentangled attention) does not tolerate `quantize_dynamic`.
- **LRU cache of ML scores** (`AGENTGUARD_ML_CACHE_SIZE`, default 4096): repeated prompts resolve in 0 ms.
- **TripleJudge is opt-in** (`AGENTGUARD_USE_TRIPLE_JUDGE`): 3 LLM API calls per prompt, reserved for very high-assurance deployments.
- **Arbiter called defensively**: `evaluate` resolved at init, 5 signatures tried, object/dict/string verdicts accepted.

## Limitations

- **Internal corpus.** `corpus_2k` was built by the project and the detection patterns (including the didactic markers) were tuned against it. The 100% / 0% figures are a regression baseline, not evidence of generalization. Results on independent public datasets will be published separately.
- **The LLM layer depends on an external API.** With no reachable arbiter, the system runs regex + ML + didactic valve + fail-closed, and benign FPR returns to about 2.3% for the duration of the outage (a deliberate trade-off: block rather than let through).
- **Tail latency.** Full-pipeline p95 is 2.7 s and p99 is 3.1 s, driven by the arbiter on flagged traffic. These depend on network conditions to the LLM provider and should not be read as an SLA.
- **Regex-only recall is 70.1%** on this corpus. Earlier README figures came from a different, smaller corpus and are not comparable.

## ONNX backend: pending validation

The ONNX Runtime integration (`agentguard/ml.py` v5.6, `scripts/export_onnx_model.py`) is **coded but not validated**.

- [ ] `pip install optimum onnxruntime onnx`
- [ ] `python scripts/export_onnx_model.py --quantize`, then sanity check: attack score > 0.6, benign score < 0.6
- [ ] A/B at FP32: `--layers regex,ml`, expected recall 100%, FPR 2.28% / 1.33% (same as torch), p50 ≤ 221 ms. **Note: the 2026-10-17 run at 221 ms was PyTorch (silent fallback, the ONNX folder did not exist).**
- [ ] A/B at int8: keep int8 only if recall stays 100% AND FPR is unchanged AND p50 is below FP32. Otherwise stay on FP32.
- [ ] Final 3-layer run (`regex,ml,llm`) on the retained backend

Rollback: `AGENTGUARD_ML_BACKEND=torch` forces the PyTorch path without touching code.

## Re-validation procedure

```powershell
# 1. Quality (always green before commit/push)
python -m ruff check .
python -m pytest tests/ -q

# 2. Full benchmark (the auto backend detects ./agentguard-model-onnx if present)
python benchmarks/run_public_benchmark.py --corpus-dir benchmarks/corpus_2k --layers regex,ml,llm --output rapport_v56_full.json
```

Success criteria (unchanged): recall ≥ 98% (target 100%), FPR benign 0%, FPR hard negatives < 3%, p50 around 400 ms.

Without LLM credit, `--layers regex,ml` remains usable for local validation: expect 100% / 2.28% / 1.33% at no cost.
