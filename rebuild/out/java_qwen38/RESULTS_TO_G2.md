# Java CPG + Qwen3.8-Max results through G3 development gate

Date: 2026-09-06

## G0 — product wiring: pass

- Python unit tests: 10/10 pass.
- Java routes to `JAVASRC` and the prompt label is `Java`; JS/TS stays `JSSRC`.
- CPG rule generation uses DashScope `qwen3.8-max` only. The returned API model field was
  `qwen3.8-max`.
- Java and JS caches are namespaced. Valid `none` results are cached as well as active rules.
- Java uses `srcMode=java`: explicit source API calls, public data-carrier parameters, and
  data-carrier `this.field` reads, while
  servlet response/request and framework context objects are excluded. This prevents
  `HttpServletResponse` receiver false paths without losing library public-API trust boundaries.
  Existing JS/Juliet `params` behavior is unchanged.
- The Java product fixed spec is curated separately from Juliet. Context-free Juliet-only
  `println -> CWE-319/CWE-526` rules were removed after they caused two reproducible safe-file
  false positives.
- Worker smoke v8: all ten checks pass, including a cross-file source-to-sink path, public API
  input, constructor-to-instance-state continuation, framework-context exclusion, and an
  `HtmlUtils.htmlEscape` sanitizer hit. Findings now also preserve the trust-boundary provenance as
  `source_kind` (`explicit_source_api`, `public_parameter`, `instance_state`, or a structural mode),
  so later ranking and critic decisions remain auditable.
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

A production-size batch of 20 was then rerun on all 41 items and also passed with role macro-F1,
sink recall, and exact-CWE sink recall all 1.000, zero missing/invalid items, and zero reversals.
It used 5 API calls including 2 validation retries (43,938 tokens, 1,613.4 cumulative API seconds).
The production default was therefore increased from 6 to 20; this reduces the prefiltered G3 set
from 94 nominal batches to 28 without weakening the G1 gate. The production request timeout was
also aligned to the evaluator's verified 600-second retry ceiling after four initial G3 requests
all hit the former 300-second limit; failed attempts remain in the raw append-only log.

## G2 — Juliet query regression: pass

All 38 CWE runs with the product `srcMode=java` exited 0. Compared with the prior `params`
baseline, raw recall decreases only 0.9 percentage points (within the preregistered 2-point
limit), while false positives fall substantially:

| unit | TP | FP | FN | precision | recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| raw line | 9,168 | 8,636 | 1,179 | 0.514940 | 0.886054 | 0.651345 |
| method/CWE instance, raw | 9,165 | 7,289 | 999 | 0.557007 | 0.901712 | 0.688632 |
| method/CWE instance, sanitized excluded | 9,115 | 5,451 | 1,049 | 0.625772 | 0.896793 | 0.737161 |

The sanitizer filter removes 1,838 FP and 50 TP at instance level. It remains enabled because it
improves F1 by 4.9 points; the final held-out still decides whether this transfers.

Reproduce the 38-CWE run without overwriting prior output:

```bash
JULIET_OUT="$PWD/benchmarks/juliet-java/out_g2_reproduction" \
JULIET_SRC_MODE=java bash benchmarks/juliet-java/run_all_cwes.sh
python3 benchmarks/juliet-java/grade_all.py out_g2_reproduction
python3 benchmarks/juliet-java/grade_instances.py \
  benchmarks/juliet-java/out_g2_reproduction \
  --output rebuild/out/java_qwen38/my_g2_instances.json
```

The raw 38-CWE output is intentionally local (about 209 MB); the compact instance reports and
timing table are retained separately.

## G3 — three real Java development repositories: CPG gate pass, legacy LLM gate fail

The repository URLs were frozen before runs and are excluded from the 12-project held-out. The
fixed Java CPG detects at least one manually vetted fix method, with the expected CWE, in all three
projects: Spark CWE-22, Plexus-utils CWE-78, and Cron-utils CWE-94. Project recall is 3/3. At the
strict method unit, it has TP=5/FP=4/FN=39 when only the project's target CWE is scored
(precision 0.556, recall 0.114). The low method recall is expected in part because `fix_info.csv`
contains supporting and test methods, while the CPG reports dangerous sink locations; the alert
burden (78 active findings, 65 for other CWEs) is retained rather than relabelled as truth.

Two general Java gaps were fixed from development evidence, without repository/function names:

- data stored from a public API input and read later as `this.field` continues the trust boundary;
- classpath resource access and validation-template construction are standard sinks, and exception
  messages may carry attacker-controlled parser text.

The deployed Qwen3.5-9B QLoRA classifier was separately tested locally on all six main-source fix
files plus the first nine negative main-source files. This fail-fast sample is deliberately marked
incomplete (15/266): binary F1 0.444 and exact-CWE F1 0.545. It produced 8/9 negative alerts and
missed 2/6 positive files, so the historical CVEfixes F1=0.805 does not transfer to this development
sample and must not be used as the final Java claim.

### Post-G3 Java architecture decision

The CVEfixes QLoRA is no longer part of Java detection. Java now defaults to
`SCANOPS_JAVA_ENGINE=cpg-qwen38`: Qwen3.8-Max generates validated Java API rules and Joern's
source-to-sink result is the verdict. The API does not call the legacy classifier for Java,
including `stop_on_first` batches and PR scans. If the CPG/Qwen runtime is unavailable, the result
is explicitly `PARTIAL`; it does not silently fall back to the poorly transferring classifier.
Other languages retain the legacy path until they receive their own evaluated engine.

Reproduce without any external model call:

```bash
python3 benchmarks/cwe-bench-java/collect_g3_candidates.py \
  --out rebuild/out/java_qwen38/my_g3_candidates.json
python3 benchmarks/cwe-bench-java/run_g3_local.py \
  --out rebuild/out/java_qwen38/my_g3_cpg.json

./llama.cpp/build/bin/llama-server \
  -m models/Qwen3.5-9B-Q4_K_M.gguf --lora models/adapter_v1_fix.gguf \
  -c 32768 --parallel 2 --host 127.0.0.1 --port 8080 -ngl 99
python3 benchmarks/cwe-bench-java/run_g3_llm.py \
  --out rebuild/out/java_qwen38/my_g3_llm.json --workers 2
```

The LLM runner writes an append-only `.jsonl` checkpoint and resumes completed files. Four local
slots were rejected after a measured Metal out-of-memory failure; two slots are the verified
configuration on this host.

### Same-file open-weight development comparison

The fixed CPG and both local Qwen variants were rescored on the identical deterministic set of six
positive and nine nominal-negative main-source files. This removes the earlier asynchronous
fail-fast sample mismatch. It is still a small development result, and nominal negatives can
contain unrelated unlabeled vulnerabilities.

| scoring | engine | precision | recall | F1 | F2 |
|---|---|---:|---:|---:|---:|
| binary | ScanOps fixed Java CPG | 0.571 | 0.667 | **0.615** | **0.645** |
| binary | Qwen3.5-9B base Q4 | 0.000 | 0.000 | 0.000 | 0.000 |
| binary | Qwen3.5-9B + CVEfixes QLoRA | 0.364 | 0.667 | 0.471 | 0.571 |
| exact CWE | ScanOps fixed Java CPG | 1.000 | 0.500 | **0.667** | **0.556** |
| exact CWE | Qwen3.5-9B base Q4 | 0.000 | 0.000 | 0.000 | 0.000 |
| exact CWE | Qwen3.5-9B + CVEfixes QLoRA | 1.000 | 0.500 | **0.667** | **0.556** |

The CPG is better than the QLoRA on binary F1 by 0.144 and ties it on exact-CWE F1, while retaining
source/sink evidence. The base model misses every labelled positive under the same prompt and token
budget. This supports removing the QLoRA from Java, but does not establish final performance: the
frozen 12-project held-out has not been opened.

### Buggy/fixed development pairs

The fixed Java CPG was also run on each project's final listed fix commit. Target-CWE alert counts
changed as follows: Spark 10→10 (8 exact file/CWE/sink-code fingerprints persisted), Plexus-utils
2→2 (0 exact fingerprints), and Cron-utils 1→0. This is a failed pair-cleanliness gate for two of
three projects and exposes missing interprocedural state/sanitizer semantics.

The counts are not automatically twelve proven false positives. Spark's fixed snapshot still has
other public resource APIs accepting untrusted paths, while Plexus-utils intentionally still allows
a caller-controlled executable array and changed shell construction rather than removing
`Runtime.exec`. Nevertheless, the engine cannot currently distinguish the CVE-fixing validation
(`file:` rejection before storing a cleaned path) or safe direct argument-vector construction from
their vulnerable forms. The correct next step is structural path semantics, not filename- or
project-specific suppression.

### Java candidate prefilter

Joern candidate extraction intentionally remains broad, but Java rule generation no longer sends
JS-only property-write candidates or calls that resolve exclusively to packages implemented inside
the repository. Standard-library, third-party, and unresolved calls are retained. On the same three
G3 repositories this reduces rule-generation candidates by 73.8% without changing the fixed CPG
findings:

| project | before | after | removed |
|---|---:|---:|---:|
| Spark | 601 | 216 | 385 |
| Plexus-utils | 1,056 | 208 | 848 |
| Cron-utils | 484 | 136 | 348 |
| total | **2,141** | **560** | **1,581** |

This is primarily a latency/cost and precision-of-rule-generation improvement. It is not counted as
a detection-score gain until a full Qwen3.8-Max rule-generation rerun passes G1 and G3.

The full dynamic G3 rerun processed and validated all 560 candidates and emitted 40 rule rows
(Spark 28, Plexus-utils 10, Cron-utils 2). It preserved TP=5, FN=39 and project recall 3/3, but
active findings rose 78→116, strict FP 69→107, and strict F1 fell 0.0847→0.0641. Target-CWE FP
also rose 4→5 and F1 fell 0.1887→0.1852. Wall time was 3,073.7 s. Including preserved failed
attempts, the append-only log has 38 calls, 9 timeout/error records, and 28 successful final
batches. This arm fails G3 and must not advance to G4.

Consequently, repository-generated Qwen3.8 rules now default to `shadow`: proposals are validated
and cached, but do not affect verdicts. `GRAPH_SPEC_DYNAMIC_RULE_MODE=enforce` is an explicit
experimental override, not the production default. Rules must be promoted through golden,
buggy/fixed, and held-out evidence before enforcement. This keeps Qwen3.8 as the only Java LLM while
preventing an unvalidated rule proposal from degrading the CPG verdict.

### Path critic safety contract

The optional LLM critic is now three-valued: `TRUE`, `FALSE`, and `UNCERTAIN`. A finding can be
suppressed only when `FALSE` has the configured confidence (`high` by default), a non-empty reason,
and a cited line that was actually present in the supplied sink/source context. Unsupported FALSE
answers are downgraded to `UNCERTAIN`; parse failures and evidence mismatches keep the finding. Raw
responses, validated verdicts, and suppression decisions are retained. The critic remains off by
default until its held-out precision gain is shown without an unacceptable recall loss.

The local Qwen3.5-9B Q4 critic was evaluated as a safe offline falsification test. It removed 24
of 78 findings, but also removed Cron-utils' only labelled hit: project recall fell from 3/3 to 2/3,
method TP from 5 to 4, and recall from 0.114 to 0.091. Although target-CWE precision rose from
0.556 to 0.571, target-CWE F1 fell from 0.189 to 0.157. It therefore fails the recall gate and is
not adopted. The result must not be represented as Qwen3.8-Max performance.

The approved Qwen3.8-Max critic then removed 9 of 78 findings while preserving TP=5, FN=39 and
project recall 3/3. Strict all-CWE FP fell from 69 to 60, precision rose from 0.0676 to 0.0769, and
F1 rose from 0.0847 to 0.0917. Target-CWE TP/FP/FN and F1 were unchanged (5/4/39, 0.1887), meaning
the removed alerts were other-CWE findings not labelled by this benchmark. The run took 590.2 s.
This passes the development no-recall-loss check but remains off by default because its benefit is
small, costly, and not yet confirmed on G4.

Reproduce the comparison after starting the base and adapter servers in turn:

```bash
python3 benchmarks/cwe-bench-java/run_g3_llm.py --url http://127.0.0.1:8081 \
  --workers 2 --max-new-files 15 --model-label 'Qwen/Qwen3.5-9B Q4_K_M base (Apache-2.0)' \
  --out rebuild/out/java_qwen38/my_base15.json
python3 benchmarks/cwe-bench-java/compare_g3_engines.py \
  --cpg rebuild/out/java_qwen38/g3_fixed_cpg_v5_scored_20260906.json \
  --llm rebuild/out/java_qwen38/g3_qwen35_base_dev15_20260906.json \
  --llm rebuild/out/java_qwen38/g3_qwen35_qlora_dev15_deterministic_20260906.json \
  --out rebuild/out/java_qwen38/my_same_file_comparison.md
```

## Metric policy

F1 remains the primary scalar because it prevents an all-alert engine (high recall, unusable
precision) and an almost-never-alert engine (high precision, unusable recall) from winning. It is
not the only gate: recall, F2, alert burden, project/CVE detection, parse failures, and buggy/fixed
pair persistence are reported separately. In particular, CWE-Bench's `fix_info.csv` contains
supporting and test methods that may have no sink; method recall alone is not a fair description of
a sink-reporting CPG engine.

## Remaining gates / no-push status

- A larger Qwen3.8-Max rule-generation batch must re-pass G1 before changing the production batch
  size. The attempted call was stopped before transmission because explicit authorization is
  required to send Java API signatures/snippets to DashScope.
- G3 full dynamic Qwen rule generation still requires explicit authorization to send repository API
  signatures/snippets to DashScope. Fixed CPG and open-weight comparisons run locally without any
  external code transfer.
- G4 compares against preregistered open-weight models on identical inputs. No remote push is
  allowed until the frozen held-out G4 F1 and recall are each within 5 percentage points of the
  strongest available comparator.
