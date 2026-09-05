# Java CPG + Qwen3.8-Max results through G2

Date: 2026-09-05

## G0 — product wiring: pass

- Python unit tests: 9/9 pass.
- Java routes to `JAVASRC` and the prompt label is `Java`; JS/TS stays `JSSRC`.
- CPG rule generation uses DashScope `qwen3.8-max` only. The returned API model field was
  `qwen3.8-max`; the separate Qwen3.5-9B classifier remains unchanged.
- Java and JS caches are namespaced. Valid `none` results are cached as well as active rules.
- Java uses `srcMode=calls`; this prevents `HttpServletResponse` and arbitrary internal method
  parameters from becoming attacker sources. Existing JS/Juliet `params` behavior is unchanged.
- The Java product fixed spec is curated separately from Juliet. Context-free Juliet-only
  `println -> CWE-319/CWE-526` rules were removed after they caused two reproducible safe-file
  false positives.
- Worker smoke v2: all seven checks pass, including a cross-file source-to-sink path and an
  `HtmlUtils.htmlEscape` sanitizer hit.
- Product orchestrator v3: one cross-file vulnerable finding, zero safe-file findings, sink line
  and path present, critic off.

Reproduce:

```bash
python3 -m unittest tests.test_graph_spec_prod_java tests.test_joern_repo_worker
python3 benchmarks/java-cpg-product/smoke_product_cpg.py \
  --out rebuild/out/java_qwen38/my_g0_worker_run.json
python3 benchmarks/java-cpg-product/smoke_product_orchestrator.py \
  --out rebuild/out/java_qwen38/my_g0_product_run.json \
  --cache rebuild/out/java_qwen38/my_g0_cache.json
```

The smoke scripts require Docker. The orchestrator smoke also loads DashScope credentials from
the repository `.env`; secrets are never written to result files.

## G1 — audited API-role development gate: pass

The 41-item view is v1 plus `rule_golden_set_v2_overrides.json`. Evidence, expected labels, BAD/OK
markers, and notes are excluded from model prompts. Production-style usage snippets are included
where receiver context is essential.

- role macro-F1: 1.000
- sink role recall: 1.000 (10/10)
- sink category+CWE exact recall: 1.000 (10/10)
- missing/invalid: 0/41
- source/sink reversals: 0
- API calls: 8 (one retry), tokens: 60,347, cumulative API wall time: 1,384.1 s

This is a development gate, not an independent final performance claim: the v2 semantic audit was
completed while diagnosing the first model run. The final CWE-Bench-Java held-out was frozen later
and is not used for tuning.

Reproduce:

```bash
python3 benchmarks/golden-sets/java/eval_rulegen.py \
  --out rebuild/out/java_qwen38/my_g1_run
```

## G2 — Juliet query regression: pass

All 38 CWE runs exited 0. The line-level totals exactly match the pre-change `out_v4` baseline:

| unit | TP | FP | FN | precision | recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| raw line | 9,261 | 12,217 | 1,086 | 0.431185 | 0.895042 | 0.581995 |
| method/CWE instance, raw | 9,258 | 10,810 | 906 | 0.461331 | 0.910862 | 0.612464 |
| method/CWE instance, sanitized excluded | 9,206 | 10,220 | 958 | 0.473901 | 0.905746 | 0.622237 |

The sanitizer filter removes 590 FP but also 52 TP at instance level. It remains enabled in the
product because it improves F1, but the lost-TP cases must be audited before any final claim.

Reproduce the 38-CWE run without overwriting prior output:

```bash
JULIET_OUT="$PWD/benchmarks/juliet-java/out_g2_reproduction" \
JULIET_SRC_MODE=params bash benchmarks/juliet-java/run_all_cwes.sh
python3 benchmarks/juliet-java/grade_all.py out_g2_reproduction
python3 benchmarks/juliet-java/grade_instances.py \
  benchmarks/juliet-java/out_g2_reproduction \
  --output rebuild/out/java_qwen38/my_g2_instances.json
```

The raw 38-CWE output is intentionally local (about 209 MB); the compact instance reports and
timing table are retained separately.
