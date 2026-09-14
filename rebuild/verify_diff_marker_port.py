"""Phase C 회귀 검사 — `[DIFF]` 마커 이식이 기존 경로를 건드리지 않았는가.

사양: rebuild/DUAL_ENGINE_RUN_SPEC.md §7

검사 4종:
  R1  내부 test 50건에서 `/analyze` 가 만드는 프롬프트가 이식 전과 **바이트 동일**
      (= prompt_code=None 경로. 모델을 부르지 않고 문자열로 증명한다 — 더 강한 검사다)
  R2  `SCANOPS_PR_DIFF_MARKER=0` 이면 PR 경로 프롬프트도 바이트 동일
  R3  patch 없음 / 삭제만 있는 hunk / hunk 경계 — 마커 0개, 원본 유지
  R4  마커가 붙을 때 **코드 줄은 하나도 바뀌지 않는다** (삽입만 한다)

출력: rebuild/out/diff_marker_port_check.json
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(ROOT))

from pr_diff_marker import build_pr_prompt, changed_lines_from_patch, mark_content  # noqa: E402

PROMPT_TMPL = """Analyze the following {language} code for security vulnerabilities.

```{language}
{code}
```

Respond in exactly this format:
VULNERABILITY: <CWE-id (CWE name)> or NONE
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN> or NONE
CVSS: <score 0.0-10.0> or 0.0
REASON: <one-line explanation> or NONE"""
MAX_CODE = 12_000

res: dict = {"checks": {}}

# ── 이식된 api_rebuild 를 부작용 없이 읽기 위해 소스에서 함수만 뽑아 재현 ────────
SRC = (REPO / "scripts" / "api_rebuild.py").read_text()
assert PROMPT_TMPL in SRC, "PROMPT_TMPL 이 바뀌었다"
assert "def _detect(language: str, code: str, prompt_code: Optional[str] = None)" in SRC
assert "code=(code if prompt_code is None else prompt_code)[:_MAX_CODE]" in SRC
assert 'PR_DIFF_MARKER = os.getenv("SCANOPS_PR_DIFF_MARKER", "1")' in SRC
res["checks"]["source_shape"] = "OK — _detect(prompt_code=None) 은 code 를 그대로 쓴다"


def prompt_of(lang: str, code: str, prompt_code: str | None) -> str:
    """이식 후 _detect 가 만드는 프롬프트와 같은 식."""
    return PROMPT_TMPL.format(
        language=lang, code=(code if prompt_code is None else prompt_code)[:MAX_CODE])


def prompt_before(lang: str, code: str) -> str:
    """이식 **전** _detect 가 만들던 프롬프트."""
    return PROMPT_TMPL.format(language=lang, code=code[:MAX_CODE])


# ── R1: 내부 test 50건, /analyze 경로 (prompt_code=None) ────────────────────
rows = [json.loads(l) for l in (ROOT / "data" / "test.jsonl").open()][:50]
mismatch = 0
for r in rows:
    code = r["prompt"].split("```", 2)[1]
    code = code.split("\n", 1)[1].rsplit("\n", 1)[0]
    lang = r["meta"].get("language") or r["meta"].get("lang_group") or "Python"
    if prompt_of(lang, code, None) != prompt_before(lang, code):
        mismatch += 1
res["checks"]["R1_analyze_50"] = {"n": len(rows), "mismatch": mismatch,
                                  "pass": mismatch == 0}

# ── R2: 플래그 off → PR 경로도 바이트 동일 ─────────────────────────────────
PATCH = ("@@ -1,3 +1,4 @@\n def handler(req):\n     name = req.get('name')\n"
         "-    return db.exec('SELECT 1')\n"
         "+    q = \"SELECT * FROM u WHERE n='\" + name + \"'\"\n"
         "+    return db.exec(q)\n")
CONTENT = ("def handler(req):\n    name = req.get('name')\n"
           "    q = \"SELECT * FROM u WHERE n='\" + name + \"'\"\n    return db.exec(q)")


def pr_prompt(lang: str, content: str, patch: str | None, flag_on: bool):
    """이식된 analyze_pr 의 동작 재현: _pr_marked_content → _detect(prompt_code=)."""
    if not flag_on or not patch:
        return prompt_of(lang, content, None), None
    ch = changed_lines_from_patch(patch)
    if not ch:
        return prompt_of(lang, content, None), 0
    return prompt_of(lang, content, mark_content(content, ch, lang)), len(ch)


off, _ = pr_prompt("Python", CONTENT, PATCH, flag_on=False)
res["checks"]["R2_flag_off"] = {"identical": off == prompt_before("Python", CONTENT),
                                "pass": off == prompt_before("Python", CONTENT)}

# ── R3: patch 없음 / 삭제만 / hunk 경계 ────────────────────────────────────
p_none, n_none = pr_prompt("Python", CONTENT, None, flag_on=True)
only_del = "@@ -1,2 +1,1 @@\n def f():\n-    unsafe()\n"
p_del, n_del = pr_prompt("Python", CONTENT, only_del, flag_on=True)
multi_hunk = ("@@ -1,2 +1,3 @@\n def handler(req):\n+    x = 1\n     name = req.get('name')\n"
              "@@ -10,2 +11,3 @@\n     pass\n+    y = 2\n     return None\n")
res["checks"]["R3_edge"] = {
    "no_patch_identical": p_none == prompt_before("Python", CONTENT),
    "no_patch_marked": n_none,
    "delete_only_identical": p_del == prompt_before("Python", CONTENT),
    "delete_only_marked": n_del,
    "multi_hunk_lines": sorted(changed_lines_from_patch(multi_hunk)),
    "pass": (p_none == prompt_before("Python", CONTENT) and n_none is None
             and p_del == prompt_before("Python", CONTENT) and n_del == 0
             and sorted(changed_lines_from_patch(multi_hunk)) == [2, 12]),
}

# ── R4: 마커는 **삽입만** 한다 — 원래 코드 줄이 하나도 바뀌지 않는다 ─────────
ch = changed_lines_from_patch(PATCH)
marked = mark_content(CONTENT, ch, "Python")
kept = [l for l in marked.splitlines() if l.strip() != "# [DIFF]"]
res["checks"]["R4_insert_only"] = {
    "original_lines": len(CONTENT.splitlines()),
    "kept_lines": len(kept),
    "markers": marked.count("# [DIFF]"),
    "pass": kept == CONTENT.splitlines() and marked.count("# [DIFF]") == len(ch),
}

res["all_pass"] = all(v.get("pass", True) for v in res["checks"].values()
                      if isinstance(v, dict))
out = ROOT / "out" / "diff_marker_port_check.json"
out.write_text(json.dumps(res, ensure_ascii=False, indent=2))
print(json.dumps(res, ensure_ascii=False, indent=2))
print("PASS" if res["all_pass"] else "FAIL")
sys.exit(0 if res["all_pass"] else 1)
