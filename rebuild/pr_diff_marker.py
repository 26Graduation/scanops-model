"""
PR 경로용 `[DIFF]` 마커 생성기 — Phase 3 후보 구현 (아직 제품에 반영하지 않았다)
=================================================================================
Phase 1 위치 상쇄 결과에서 살아남은 유일한 형식이 **P2(`[DIFF]` 마커)** 다.
그 형식을 제품 PR 경로에 쓰려면 **GitHub patch(unified diff) → head 파일의 변경 줄 번호**
매핑이 필요하다. 이 파일은 그 매핑 하나만 담는다.

**아직 `scripts/api_rebuild.py` 를 고치지 않았다.** 사전등록상 제품 반영은
`PROMPT-WIN` 또는 `ADOPT` 일 때만 하기로 돼 있고, Phase 1 은 `CB-PARTIAL` 이었다.
이 파일은 **검증된 부품**으로 먼저 두고, 게이트가 열리면 그때 붙인다.

평가와 제품의 차이 (그대로 적는다):
  - 평가에서는 A/B 중립 라벨을 썼다 — 벤치가 "취약=이전판본"이라 순서가 라벨을 흘리기 때문이다.
  - **제품에서는 그 문제가 없다.** base→head 는 사실이고 라벨이 아니다.
    따라서 제품 프롬프트에는 중립 라벨이 필요 없다. 마커만 넣는다.

실행(자체 검증): python3 rebuild/pr_diff_marker.py
"""
from __future__ import annotations

import re

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

LINE_COMMENT = {
    "Python": "#", "Ruby": "#", "PHP": "//", "Java": "//", "JavaScript": "//",
    "TypeScript": "//", "JS/TS": "//", "C": "//", "C++": "//", "C/C++": "//",
    "Go": "//", "C#": "//", "Kotlin": "//", "Rust": "//",
}


def changed_lines_from_patch(patch: str | None) -> set[int]:
    """unified diff → **head 파일 기준 1-based 변경(추가) 줄 번호** 집합.

    `-` 줄(삭제)은 head 에 없으므로 표시할 수 없다. head 에 존재하는 것은 `+` 줄뿐이다.
    삭제만 있는 hunk 는 표시할 줄이 없다 — 그 사실을 그대로 둔다(억지로 근처 줄을 찍지 않는다).
    """
    if not patch:
        return set()
    out: set[int] = set()
    new_ln = None
    for line in patch.splitlines():
        m = HUNK.match(line)
        if m:
            new_ln = int(m.group(1))
            continue
        if new_ln is None:
            continue
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            out.add(new_ln)
            new_ln += 1
        elif line.startswith("-"):
            pass                      # head 에 없는 줄
        else:
            new_ln += 1               # 문맥 줄
    return out


def mark_content(content: str, changed: set[int], language: str) -> str:
    """변경 줄 **앞 줄**에 `<주석> [DIFF]` 를 넣는다 (평가에서 쓴 P2 와 같은 형태)."""
    c = LINE_COMMENT.get(language, "//")
    out: list[str] = []
    for i, line in enumerate(content.splitlines(), start=1):
        if i in changed:
            indent = line[:len(line) - len(line.lstrip())]
            out.append(f"{indent}{c} [DIFF]")
        out.append(line)
    return "\n".join(out)


def build_pr_prompt(language: str, content: str, patch: str | None, tmpl: str) -> tuple[str, int]:
    """제품 PR 프롬프트. 반환 (프롬프트, 표시한 변경 줄 수).

    변경 줄이 하나도 없으면 **원본 그대로** 쓴다 — 마커가 없는 입력은 현행과 동일하다.
    """
    changed = changed_lines_from_patch(patch)
    if not changed:
        return tmpl.format(language=language, code=content), 0
    marked = mark_content(content, changed, language)
    return tmpl.format(language=language, code=marked), len(changed)


# ── 자체 검증 ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    content = "\n".join([
        "def handler(req):",              # 1
        "    name = req.get('name')",     # 2
        "    q = \"SELECT * FROM u WHERE n='\" + name + \"'\"",  # 3  ← 추가된 줄
        "    return db.exec(q)",          # 4
    ])
    patch = (
        "@@ -1,3 +1,4 @@\n"
        " def handler(req):\n"
        "     name = req.get('name')\n"
        "-    return db.exec('SELECT 1')\n"
        "+    q = \"SELECT * FROM u WHERE n='\" + name + \"'\"\n"
        "+    return db.exec(q)\n"
    )
    ch = changed_lines_from_patch(patch)
    assert ch == {3, 4}, f"변경 줄 매핑 실패: {ch}"
    marked = mark_content(content, ch, "Python")
    assert marked.count("# [DIFF]") == 2, marked
    lines = marked.splitlines()
    assert lines[2].strip() == "# [DIFF]" and "SELECT * FROM" in lines[3], marked

    # 삭제만 있는 patch → 표시할 줄 없음 → 원본 그대로
    only_del = "@@ -1,2 +1,1 @@\n def f():\n-    unsafe()\n"
    assert changed_lines_from_patch(only_del) == set()
    tmpl = "Analyze the following {language} code.\n\n```{language}\n{code}\n```"
    p, n = build_pr_prompt("Python", content, only_del, tmpl)
    assert n == 0 and "[DIFF]" not in p

    # patch 없음 → 현행과 동일
    p2, n2 = build_pr_prompt("Python", content, None, tmpl)
    assert n2 == 0 and p2 == tmpl.format(language="Python", code=content)

    print("자체 검증 통과 — 변경 줄 매핑 {3,4}, 마커 2개, 삭제-only·patch-없음은 원본 유지")
    print(marked)
