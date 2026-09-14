"""GRAPH-SPEC R4 STEP 5 — 정답 라인 필터 + 평가셋 선정 기준 적용.

**모든 삭제 라인을 정답으로 취급하지 않는다.** 재현 가능한 필터를 순서대로 적용하고
각 단계 통과 수를 기록한다. 기준 적용 전/후 정답 라인 수를 둘 다 남긴다.

필터 (F8 은 이번 라운드 미적용 — 이유는 산출물에 기록)
  F1 diff 에 JS/TS 파일이 있는가
  F2 삭제 라인이 존재하는가 (추가만 있는 수정은 '취약 라인'을 지목할 수 없다)
  F3 테스트·문서·빌드산출물·벤더 경로 제외
  F4 노이즈 라인 제외 (공백·주석만·닫는 괄호만·import 재배치)
  F5 CWE 유형과 라인 구문의 부합
  F6 대량 변경 커밋 제외 (리팩터 혼입 위험)
  F7 v4_meta 의 file_paths 에 있는 파일만
  F8 (미적용) 삭제 라인이 CPG 상 sink 또는 sink 인자인가 — 레포별 CPG 필요

출력: rebuild/out/r4_cvefixes_filter_r4.json
      rebuild/data/repo_bench/cvefixes_linetruth_r4.jsonl   (필터 통과분)
"""
from __future__ import annotations

import ast
import json
import re
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
DATA = ROOT / "data" / "repo_bench"

EXT_JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

# F3 — 경로 제외 패턴 (일반 규칙. 특정 레포 이름 없음)
PATH_EXCLUDE = re.compile(
    r"(^|/)(test|tests|__tests__|spec|specs|e2e|fixtures?|mocks?|examples?|docs?|"
    r"vendor|third_party|node_modules|dist|build|coverage|migrations?)(/|$)"
    r"|\.(min|bundle)\.js$|\.(md|txt|json|lock|yml|yaml|snap)$", re.I)

# F4 — 노이즈 라인
NOISE = re.compile(r"^\s*$|^\s*(//|/\*|\*|\*/|#)|^\s*[)}\];,]+\s*$", )
IMPORT_ONLY = re.compile(r"^\s*(import\b|const\s+\w+\s*=\s*require\(|require\(|export\s+\{)")

# F5 — CWE 유형 → 그 결함이 나타날 수 있는 구문 키워드 (일반 API·언어 구문만)
CWE_SYNTAX = {
    "CWE-89": r"query|exec|SELECT|INSERT|UPDATE|DELETE|WHERE|sequelize|knex|\$\{|\+\s*req|concat",
    "CWE-943": r"find|update|insert|remove|delete|aggregate|\$where|\$ne|\$gt|collection|mongo",
    "CWE-78": r"exec|spawn|execFile|child_process|system|shell",
    "CWE-77": r"exec|spawn|command|shell",
    "CWE-94": r"eval|new Function|vm\.|runInContext|require\(",
    "CWE-79": r"html|render|send|write|innerHTML|escape|sanitiz|<%|res\.|\$\{|body|title|name|desc",
    "CWE-80": r"html|escape|sanitiz|render",
    "CWE-22": r"path|join|resolve|readFile|writeFile|__dirname|\.\./|sendFile|createReadStream",
    "CWE-601": r"redirect|location|url|href|returnTo",
    "CWE-284": r"auth|session|user|role|permi|admin|token|isAuthor|access|owner",
    "CWE-862": r"auth|session|user|role|permi|admin|token|isAuthor|middleware",
    "CWE-863": r"auth|session|user|role|permi|admin|token|isAuthor|owner|id",
    "CWE-639": r"user|id|owner|params|body",
    "CWE-287": r"password|login|auth|hash|bcrypt|compare|token|session",
    "CWE-307": r"attempt|limit|throttle|lock|count|fail",
    "CWE-384": r"session|cookie|regenerate|sid",
    "CWE-200": r"password|secret|token|key|email|user|log|console|res\.",
    "CWE-20": r"valid|check|parse|Number|typeof|schema|sanitiz|req\.",
    "CWE-1321": r"__proto__|prototype|constructor|merge|extend|assign|deep",
    "CWE-400": r"limit|size|length|timeout|max|regex|loop",
    "CWE-770": r"limit|size|max|quota|rate",
}
F6_MAX_DELETED_PER_COMMIT = 30      # 임계값 — 근거는 산출물 note 참조


def main() -> None:
    meta = [json.loads(l) for l in (ROOT / "data" / "v4_meta.jsonl").open()]
    mmap = {(r["cve_id"], r["hash"]): r for r in meta}
    raw = json.loads((OUT / "r4_cvefixes_linetruth_raw.json").read_text())
    diffs = json.loads((OUT / "r4_cvefixes_diffs_git.json").read_text())["diffs"]

    def parse_fps(r):
        v = r.get("file_paths")
        if isinstance(v, str):
            try:
                v = ast.literal_eval(v)
            except Exception:
                v = []
        return v or []

    # 삭제 라인의 원문을 diff 에서 되찾는다 (F4/F5 판정용)
    def deleted_text_map(diff: str) -> dict[tuple, str]:
        out, cur, old = {}, None, None
        for line in diff.splitlines():
            if line.startswith("diff --git"):
                m = re.search(r" a/(\S+) b/(\S+)$", line); cur = m.group(1) if m else None; old = None
            elif line.startswith("@@") and cur:
                m = re.match(r"@@ -(\d+)", line); old = int(m.group(1)) if m else None
            elif old is not None and cur:
                if line.startswith("-") and not line.startswith("---"):
                    out[(cur, old)] = line[1:]; old += 1
                elif line.startswith("+") and not line.startswith("+++"):
                    pass
                elif line.startswith("\\"):
                    pass
                else:
                    old += 1
        return out

    trace = {f"F{i}": {"cve_통과": 0, "라인_통과": 0} for i in range(1, 8)}
    cve_drop: dict[str, list] = {f"F{i}": [] for i in range(1, 8)}
    kept_rows, per_cve = [], []
    n_raw_lines = raw["n_raw_truth_rows"]

    for c in raw["per_cve"]:
        cve, sha = c["cve_id"], c["hash"]
        r = mmap[(cve, sha)]
        dtext = deleted_text_map(diffs[f"{cve}|{sha}"])
        allow_fps = {p for p in parse_fps(r)}
        cwe = (c["cwe_id"] or "").strip()
        rec = {"cve_id": cve, "repo": f"{c['owner']}/{c['repo']}", "cwe_id": cwe,
               "cvss3": c["cvss3"], "n_deleted_raw": c["n_deleted_lines_js"], "drops": []}

        # F1
        if c["n_js_files_in_diff"] == 0:
            rec["drops"].append("F1 diff 에 JS/TS 파일 없음"); cve_drop["F1"].append(cve)
            per_cve.append(rec); continue
        trace["F1"]["cve_통과"] += 1; trace["F1"]["라인_통과"] += c["n_deleted_lines_js"]
        # F2
        if c["n_deleted_lines_js"] == 0:
            rec["drops"].append("F2 삭제 라인 0 (추가만 있는 수정)"); cve_drop["F2"].append(cve)
            per_cve.append(rec); continue
        trace["F2"]["cve_통과"] += 1; trace["F2"]["라인_통과"] += c["n_deleted_lines_js"]
        # F6
        if c["n_deleted_lines_js"] > F6_MAX_DELETED_PER_COMMIT:
            rec["drops"].append(f"F6 삭제 라인 {c['n_deleted_lines_js']} > {F6_MAX_DELETED_PER_COMMIT}")
            cve_drop["F6"].append(cve); per_cve.append(rec); continue

        kept_this = []
        n_f3 = n_f4 = n_f5 = n_f7 = 0
        for f, v in c["files"].items():
            if PATH_EXCLUDE.search(f):
                continue
            for ln in v["deleted"]:
                n_f3 += 1
                txt = dtext.get((f, ln), "")
                if NOISE.match(txt) or IMPORT_ONLY.match(txt):
                    continue
                n_f4 += 1
                pat = CWE_SYNTAX.get(cwe)
                if pat and not re.search(pat, txt, re.I):
                    continue
                n_f5 += 1
                if allow_fps and f not in allow_fps:
                    continue
                n_f7 += 1
                kept_this.append({
                    "id": f"cvefixes:{cve}:{f}:{ln}",
                    "repo": f"{c['owner']}/{c['repo']}", "commit": sha, "cve_id": cve,
                    "sink_file": f, "sink_line": ln, "line_text": txt.strip()[:200],
                    "category": None, "cwe": cwe, "cvss": c["cvss3"],
                    "is_code_file": True, "source_file": None, "source_line": None,
                    "cross_file": False, "cross_file_candidate": False,
                    "confidence": "filtered_deleted_line",
                    "evidence_kind": "git show 삭제(-) 라인 + F3~F7 필터 통과",
                })
        trace["F3"]["라인_통과"] += n_f3; trace["F4"]["라인_통과"] += n_f4
        trace["F5"]["라인_통과"] += n_f5; trace["F7"]["라인_통과"] += n_f7
        for k in ("F3", "F4", "F5", "F7"):
            trace[k]["cve_통과"] += 1
        trace["F6"]["cve_통과"] += 1; trace["F6"]["라인_통과"] += c["n_deleted_lines_js"]
        rec.update({"n_after_F3": n_f3, "n_after_F4": n_f4, "n_after_F5": n_f5,
                    "n_after_F7": n_f7, "n_kept": len(kept_this)})
        if not kept_this:
            rec["drops"].append("필터 통과 라인 0")
        kept_rows.extend(kept_this)
        per_cve.append(rec)

    # 카테고리 채우기 (CWE 기반, 참고용)
    from r4_cvefixes_linetruth import CWE_TO_CAT
    for x in kept_rows:
        x["category"] = CWE_TO_CAT.get(x["cwe"], "Miscellaneous")

    kept_cves = sorted({x["cve_id"] for x in kept_rows})
    kept_repos = sorted({x["repo"] for x in kept_rows})
    lines_per_cve = {}
    for x in kept_rows:
        lines_per_cve[x["cve_id"]] = lines_per_cve.get(x["cve_id"], 0) + 1

    n_sample = raw.get("stats", {}).get("n_sample", len(raw.get("per_cve", [])))
    out = {
        "round": 4, "step": "STEP 5 — 정답 라인 필터 + 평가셋 선정 기준",
        "표본": n_sample,
        "정답라인_필터_전": n_raw_lines,
        "정답라인_필터_후": len(kept_rows),
        "감소율": round(1 - len(kept_rows) / n_raw_lines, 4) if n_raw_lines else None,
        "filter_trace": trace,
        "filters": {
            "F1": "diff 에 JS/TS 파일이 있는가",
            "F2": "삭제 라인이 존재하는가 (추가만 있는 수정 제외)",
            "F3": f"경로 제외 정규식: {PATH_EXCLUDE.pattern[:90]}…",
            "F4": "노이즈 라인 제외 (공백·주석만·닫는 괄호만·import/require 문)",
            "F5": "CWE 유형과 라인 구문의 부합 (CWE_SYNTAX 표, 일반 API·언어 구문만)",
            "F6": f"커밋당 삭제 라인 ≤ {F6_MAX_DELETED_PER_COMMIT}",
            "F7": "v4_meta 의 file_paths 목록에 있는 파일만",
            "F8_미적용": ("삭제 라인이 CPG 상 sink 또는 sink 인자인가. 레포별 Joern CPG 가 필요해 "
                          "STEP 7 파일럿에서만 적용 가능하다. 정답표 생성 단계에 넣으면 "
                          "**평가 대상 도구가 정답을 정의하는 순환**이 되므로 의도적으로 넣지 않았다."),
        },
        "F5_주의": ("F5 는 휴리스틱이다. CWE 유형별 키워드 부합을 본 것이고 '이 라인이 취약의 원인'을 "
                    "증명하지 않는다. 통과 전/후 수를 둘 다 남긴 이유가 이것이다."),
        "F6_근거": (f"삭제 라인이 {F6_MAX_DELETED_PER_COMMIT} 을 넘는 커밋은 리팩터·대량 정리가 섞여 "
                    "취약 라인을 특정할 수 없다. 표본에서 이 임계값에 걸린 CVE 와 그 삭제 라인 수를 "
                    "아래 dropped_by_filter 에 남겼다."),
        "dropped_by_filter": {k: v for k, v in cve_drop.items() if v},
        "결과": {
            "통과_CVE": len(kept_cves), "통과_레포": len(kept_repos),
            "통과_정답라인": len(kept_rows),
            "CVE당_정답라인_중앙값": statistics.median(lines_per_cve.values()) if lines_per_cve else None,
            "CVE당_정답라인_평균": round(statistics.mean(lines_per_cve.values()), 1) if lines_per_cve else None,
            "레포_목록": kept_repos,
            "lines_per_cve": lines_per_cve,
        },
        "확장_추정": {
            "전체_후보_pool": 977,
            "표본_통과율_CVE": round(len(kept_cves) / n_sample, 4) if n_sample else None,
            "주의": (f"표본 {n_sample}건의 통과율을 977 에 곱해 '몇 건 나온다'로 쓰지 않는다. "
                     "표본은 cve_id 정렬 앞쪽부터라 무작위 추출이 아니다. "
                     "실제 확장 시 전수 적용해 센다."),
        },
        "per_cve": per_cve,
    }
    (OUT / "r4_cvefixes_filter_r4.json").write_text(json.dumps(out, ensure_ascii=False, indent=2))
    with (DATA / "cvefixes_linetruth_r4.jsonl").open("w") as fh:
        for x in kept_rows:
            fh.write(json.dumps(x, ensure_ascii=False) + "\n")
    print(json.dumps({k: out[k] for k in ("정답라인_필터_전", "정답라인_필터_후", "감소율",
                                          "dropped_by_filter", "결과")},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
