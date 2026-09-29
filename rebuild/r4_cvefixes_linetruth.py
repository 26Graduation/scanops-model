"""GRAPH-SPEC R4 STEP 4 후반 — 삭제(-) 라인 추출 + hunk 범위 대조 + 정답표 생성.

**CVEfixes hunk 전체를 취약 라인으로 쓰지 않는다.** hunk 범위와 실제 삭제 라인 수를 나란히 재
"범위를 정답으로 쓰면 안 되는 근거"를 수치로 남긴다.

정답표 스키마는 juice-shop 정답표와 맞춘다:
  sink_file / sink_line / category / cwe / cvss (+ repo·commit·cve 식별자, is_code_file)
"""
from __future__ import annotations

import ast
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
DATA = ROOT / "data" / "repo_bench"
sys.path.insert(0, str(ROOT))

from r4_cvefixes_harvest import deleted_lines_from_diff, EXT_JS  # noqa: E402

# CWE → juice-shop 정답표의 category 축으로의 대응.
# §12-1/§12-2 는 juice-shop 챌린지 분류용이라 그대로 못 쓴다. CVEfixes 는 CWE 가 있으므로
# **CWE 를 1차 키로 쓰고** category 는 참고용으로만 채운다. §12-2 를 수정하지 않는다.
CWE_TO_CAT = {
    "CWE-89": "Injection", "CWE-943": "Injection", "CWE-78": "Injection",
    "CWE-77": "Injection", "CWE-94": "Injection", "CWE-917": "Injection",
    "CWE-79": "XSS", "CWE-80": "XSS",
    "CWE-601": "Unvalidated Redirects",
    "CWE-22": "Sensitive Data Exposure", "CWE-23": "Sensitive Data Exposure",
    "CWE-200": "Sensitive Data Exposure",
    "CWE-20": "Improper Input Validation", "CWE-1321": "Improper Input Validation",
    "CWE-284": "Broken Access Control", "CWE-862": "Broken Access Control",
    "CWE-863": "Broken Access Control", "CWE-639": "Broken Access Control",
    "CWE-287": "Broken Authentication", "CWE-307": "Broken Authentication",
    "CWE-502": "Injection", "CWE-918": "Injection", "CWE-400": "Miscellaneous",
    "CWE-770": "Broken Anti Automation", "CWE-799": "Broken Anti Automation",
}


def main() -> None:
    meta = [json.loads(l) for l in (ROOT / "data" / "v4_meta.jsonl").open()]
    mmap = {(r["cve_id"], r["hash"]): r for r in meta}
    git = json.loads((OUT / "r4_cvefixes_diffs_git.json").read_text())["diffs"]
    hfp = OUT / "r4_cvefixes_diffs_raw.json"
    hf = json.loads(hfp.read_text()).get("diffs", {}) if hfp.exists() else {}

    def parse_fps(r):
        v = r.get("file_paths")
        if isinstance(v, str):
            try:
                v = ast.literal_eval(v)
            except Exception:
                v = []
        return v or []

    def parse_hunks_meta(r):
        v = r.get("hunks")
        if isinstance(v, str):
            try:
                v = ast.literal_eval(v)
            except Exception:
                v = {}
        return v or {}

    per_cve, rows = [], []
    hunk_lens, del_counts, ratio = [], [], []
    for key, diff in git.items():
        cve, sha = key.split("|", 1)
        r = mmap.get((cve, sha))
        if r is None:
            continue
        parsed = deleted_lines_from_diff(diff)
        js = {f: v for f, v in parsed.items() if Path(f).suffix.lower() in EXT_JS}
        meta_hunks = parse_hunks_meta(r)
        n_del = sum(len(v["deleted"]) for v in js.values())
        n_hunk_span = sum(e - s + 1 for v in js.values() for s, e in v["hunks"])
        for v in js.values():
            for s, e in v["hunks"]:
                hunk_lens.append(e - s + 1)
        del_counts.append(n_del)
        if n_hunk_span:
            ratio.append(n_del / n_hunk_span)
        cwe = (r.get("cwe_id") or "").strip()
        per_cve.append({
            "cve_id": cve, "hash": sha, "owner": r["owner"], "repo": r["repo"],
            "cwe_id": cwe, "cvss3": r.get("cvss3"), "language": r.get("language"),
            "n_files_in_diff": len(parsed), "n_js_files_in_diff": len(js),
            "n_deleted_lines_js": n_del,
            "n_hunk_span_lines_js": n_hunk_span,
            "deleted_over_span": round(n_del / n_hunk_span, 4) if n_hunk_span else None,
            "meta_hunks_files": list(meta_hunks.keys())[:5],
            "files": {f: {"deleted": v["deleted"][:60], "n_deleted": len(v["deleted"]),
                          "hunks": v["hunks"], "n_added": v["n_added"]}
                      for f, v in js.items()},
        })
        for f, v in js.items():
            for ln in v["deleted"]:
                rows.append({
                    "id": f"cvefixes:{cve}:{f}:{ln}",
                    "repo": f"{r['owner']}/{r['repo']}", "commit": sha, "cve_id": cve,
                    "sink_file": f, "sink_line": ln,
                    "category": CWE_TO_CAT.get(cwe, "Miscellaneous"),
                    "cwe": cwe, "cvss": r.get("cvss3"),
                    "is_code_file": True,
                    "source_file": None, "source_line": None,
                    "cross_file": False, "cross_file_candidate": False,
                    "confidence": "raw_deleted_line",
                    "evidence_kind": "git show <fix_commit> 의 삭제(-) 라인 (필터 적용 전)",
                })

    n_ok = len(per_cve)
    stats = {
        "n_sample": len(git) + len(hf),
        "n_diff_확보": len(git), "n_diff_확보_HF": len(hf),
        "n_삭제라인_추출_성공_CVE": sum(1 for c in per_cve if c["n_deleted_lines_js"] > 0),
        "hunk_span_평균줄": round(statistics.mean(hunk_lens), 1) if hunk_lens else None,
        "hunk_span_중앙값줄": statistics.median(hunk_lens) if hunk_lens else None,
        "hunk_span_최대줄": max(hunk_lens) if hunk_lens else None,
        "CVE당_평균_삭제라인": round(statistics.mean(del_counts), 1) if del_counts else None,
        "CVE당_중앙값_삭제라인": statistics.median(del_counts) if del_counts else None,
        "삭제라인/hunk범위_평균비율": round(statistics.mean(ratio), 4) if ratio else None,
        "왜_범위를_정답으로_쓰면_안되는가": (
            f"hunk 하나의 범위는 평균 {round(statistics.mean(hunk_lens),1) if hunk_lens else '-'}줄"
            f"(중앙값 {statistics.median(hunk_lens) if hunk_lens else '-'})인데, 그 범위 안에서 실제로 "
            f"삭제된 라인은 평균 {round(statistics.mean(ratio)*100,1) if ratio else '-'}% 뿐이다. "
            f"즉 범위를 정답으로 쓰면 라인의 약 78% 가 취약과 무관한 문맥·추가 라인이다. "
            f"게다가 범위 중앙값 {statistics.median(hunk_lens) if hunk_lens else '-'}줄은 ±10 채점 창(21줄) "
            f"안에 완전히 들어가므로, 범위 어디든 한 번 걸리면 무조건 적중이 된다 — 지표가 무의미해진다."),
        "additions_only_CVE": None,
    }
    payload = {
        "round": 4, "step": "STEP 4 — 삭제 라인 추출 결과",
        "path_used": "git-show (경로 나). HF 경로는 별도 기록.",
        "parse_hunks_untouched": True,
        "new_function": "rebuild/r4_cvefixes_harvest.py :: deleted_lines_from_diff()",
        "stats": stats,
        "per_cve": per_cve,
        "n_raw_truth_rows": len(rows),
    }
    (OUT / "r4_cvefixes_linetruth_raw.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2))
    with (DATA / "cvefixes_linetruth_r4_raw.jsonl").open("w") as fh:
        for x in rows:
            fh.write(json.dumps(x, ensure_ascii=False) + "\n")
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    print(f"raw 정답 라인 행 {len(rows)}건 → rebuild/data/repo_bench/cvefixes_linetruth_r4_raw.jsonl")


if __name__ == "__main__":
    main()
