# Java Rule-Generation Golden Set v1 — Summary

Golden set for grading ScanOps graph-engine **stage (2) rule generation**: given an API call
extracted from a Java CPG, classify it as `source` / `sink` / `sanitizer` / `none`. Derived
entirely from `securibench-micro` (Apache-2.0, 123 test files across 12 categories), the only
Java taint-labeled corpus already vetted in this project (see
`scanops-model/benchmarks/securibench-micro/ground_truth.json` and the roadmap doc's section 6 log
entry dated 2026-09-02).

File: `rule_golden_set_v1.json` - 41 entries (one per distinct API/role pair), schema aligned
to `scanops/core/graph_spec_prod.py`'s `RULEGEN_SYSTEM` LLM output shape (`role`, `cat`, `cwe`,
`applies_to`) and its `CATS` dict's 14 category slugs, so this file can be fed straight into
grading both the hand rules (`joern/sanitizers.json`, `HAND_JSSRC`/`HAND_SRC`) and the LLM
rule-generation fallback path once Java is wired up.

## Counts

| role | count |
|---|---|
| source | 18 |
| sink | 9 |
| sanitizer | 2 (+1 corpus-local, non-reusable - see gaps) |
| none | 12 |
| **total** | **41** |

7 entries are marked `confidence: needs-review` because their only supporting evidence file is
one of the 9 known `declared_vuln_count`-vs-`/* BAD */`-marker mismatches already logged in the
roadmap doc (`aliasing/Aliasing2,4`, `basic/Basic26,31`, `collections/Collections10,11`,
`datastructures/Datastructures4`, `inter/Inter10`, `pred/Pred2`). In most of those cases the
*API role itself* is not actually in doubt (e.g. `getCookies()` is unambiguously a source) - the
flag is about the specific line/count evidence, not the classification.

## Coverage vs. the existing 14-category rule table

`scanops/core/graph_spec_prod.py`'s `CATS` dict defines 14 categories. securibench-micro gives
usable Java examples for only **4 of them**:

| category | CWE | securibench-micro examples? |
|---|---|---|
| xss | CWE-79 | **Yes** - dominant, ~100+ of 123 files (`println`) |
| sqli | CWE-89 | **Yes** - `basic/Basic19-21` (`prepareStatement`, `execute`, `executeUpdate`, `executeQuery`) |
| pathtraver | CWE-22 | **Yes** - `basic/Basic22-23` (`createNewFile`, `FileWriter`, `FileInputStream`) |
| redirect | CWE-601 | **Yes** - `basic/Basic24`, `sanitizers/Sanitizers3,5` (`sendRedirect`, plus a real sanitizer: `URLEncoder.encode`) |
| cmdi | CWE-78 | **None** |
| ssrf | CWE-918 | **None** |
| deser | CWE-502 | **None** |
| codei | CWE-94 | **None** |
| nosqli | CWE-943 | **None** |
| logforge | CWE-117 | **None** |
| sensitive | CWE-200 | **None** |
| accesscontrol | CWE-284 | **None** |
| weakcrypto | CWE-327 | **None** |
| proto | CWE-1321 | **None** (JS/TS-specific concept anyway - prototype pollution doesn't apply to Java) |

**9 of 14 categories have zero securibench-micro coverage.** This was expected - the corpus
predates most of these CWE classes' current tooling focus and is XSS/SQLi/path-traversal/
redirect-centric by design (it was built to stress interprocedural/aliasing/collection taint
*propagation*, not to catalog every vulnerability class).

## Sanitizer coverage - the known gap, confirmed and narrowed

Re-derivation confirmed the pre-session finding: **almost every "sanitizer" test case in this
corpus routes through a locally-defined `clean(String)` helper method**, not a reusable generic
library API - a rule keyed on the literal name `clean` would false-positive on unrelated code.
One real exception was found on closer read: `sanitizers/Sanitizers3.java` and
`Sanitizers5.java` show `java.net.URLEncoder.encode(...)` genuinely neutralizing a redirect-
target injection (CWE-601) - this **is** a reusable generic sanitizer, and it is **not currently
present** in `joern/sanitizers.json`'s `JAVASRC` or `common` sections for the `redirect`
category. Recommend adding it.

`Sanitizers5.java` also surfaces an adversarial trap worth keeping as an explicit test case:
`URLDecoder.decode()` called on the encoded value **re-introduces** the taint
(`sendRedirect(dec)` is BAD, `sendRedirect(enc)` is OK in the same file) - a rule-gen approach
that treats "encoded somewhere upstream" as sufficient sanitization, rather than checking the
value actually used at the sink, will misclassify this file.

## Other findings worth the team's attention

- **Conflict with the existing hand-tuned rule table**: `joern/sanitizers.json`'s
  `common.sqli` section currently treats bare `prepareStatement(` / `PreparedStatement` as a
  **sanitizer** signal (parameterized-query heuristic). `basic/Basic19.java`
  ("simple SQL injection with prepared statements") is a direct counter-example - `prepareStatement`
  is called with a string built via concatenation of tainted input, and is marked `/* BAD */`.
  The parameterization signal needs to come from `?` placeholders in the SQL literal (and/or a
  later `.setString`/`.setInt` call), not from the mere presence of `prepareStatement(`. This is
  a plausible **false-negative source** in the current rule table for real Java SQLi.
- Several BAD-line calls that a naive frequency-count approach (the starting-point list handed
  into this task) would flag as sink candidates are **not actually sinks**: `toString()`,
  `toLowerCase()`, `nextToken()`/`nextElement()`, `getContents()`/`getData()` (synthetic test
  classes), and collection accessors like `.get()`/`.getLast()`/`.getValue()` - they only
  co-occur on the same source line as the real sink (`println`). All corrected to `role: none`
  in this golden set with notes explaining why.
- `HttpSession.setAttribute`/`.getAttribute` and Java reflection (`Method.invoke`,
  `Class.forName`, etc.) are exercised by the `session` and `reflection` categories but test
  taint *propagation*, not a vulnerability class of their own. `scanops/core/java_graph.py`
  already informally tracks `.setAttribute(`/`.putValue(` as a `trustbound` category (roughly CWE-501),
  which is **not** one of the official 14 categories - flagged as an open question for the team,
  not resolved here.

## Explicitly out of scope / limitation

**This corpus alone is too small and too narrow to be a complete Java golden set.** 123 files
covering essentially 4 of 14 categories, with sanitizer coverage limited to one real API, is a
useful *starting point* (per the roadmap's Phase 1 plan) but not sufficient for grading rule
generation across the full category set the team cares about. The planned next expansion is the
**NIST Juliet Java Test Suite** (CWE-tagged, tens of thousands of Java test cases across a much
broader CWE range, already scoped in the roadmap doc's sections 3/4 as the next action item) -
downloading/processing it was explicitly out of scope for this task and was not attempted. A
second useful future source, not attempted here either, would be mining OWASP Benchmark's Java
cases (already referenced in `scanops/core/java_graph.py`) for source/sink pairs beyond the
taint-verdict logic that file currently implements.

## Files

- `rule_golden_set_v1.json` - the golden set (41 entries)
- `SUMMARY.md` - this file

Both under `scanops-model/benchmarks/golden-sets/java/`.
