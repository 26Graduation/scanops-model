# Java rule-generation golden set v2 audit

Date: 2026-09-05

The v2 evaluation view is the 41 v1 entries with
`rule_golden_set_v2_overrides.json` applied by exact `api` key. The original v1 file remains
immutable so every correction is reviewable.

## Resolved labels

- `getParameterMap` remains `source`; confidence is raised to `high`. In `Basic26.java`, the
  value from `req.getParameterMap()` reaches `writer.println(e.getValue())`. The missing BAD
  comment is a marker defect.
- `getCookies` remains `source`; confidence is raised to `high`. `Basic31.java` contains three
  BAD cookie-derived writes while its declaration says two. The count is stale, but the API
  semantics are unambiguous.
- local `clean(String)` changes from `sanitizer` to `none`. Its name is repository-local and its
  implementation varies: `Sanitizers1` encodes dangerous characters, while `Sanitizers4` only
  handles `&` and is deliberately unsafe. A reusable rule keyed on `clean` would overfit the
  benchmark and contradict `RULEGEN_SYSTEM` hard rule 1.
- `getAuthType`, `getScheme`, `getProtocol`, `getInitParameter`, and
  `getInitParameterNames` change from `source` to `none`. SecuriBench propagates these values to
  exercise analysis, but constrained container/deployment metadata is not arbitrary
  request-controlled input under the production threat model.
- the grouped reflection entry changes from `none` to `sink/reflection/CWE-470`.
  `Class.forName` and reflective invocation/instantiation selected by tainted identifiers are
  precisely the general CWE-470 behavior represented by the engine's `reflection` category.
- `println` and `URLEncoder.encode` receive short, label-free usage snippets because production
  candidates include snippets. A bare method name is insufficient to distinguish an HTTP response
  writer from console output or redirect-target encoding from unrelated encoding.

## Evaluation consequence

The resolved v2 set has 13 sources, 10 sinks, 1 reusable sanitizer, and 17 `none` entries. It is
used only for general API-role generation. Corpus-local dataflow behavior is evaluated in the
end-to-end benchmark instead of being leaked into the rule generator.
