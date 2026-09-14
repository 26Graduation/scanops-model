"""L1 top-N 채점 — GRAPH_RUN_SPEC.md §17-3/§17-4. §16-4와 같은 구조, "잘못된 라인"만 재정의.

line_hit_loose_topN  = file_hit AND (후보 중 하나라도 |후보라인 − 정답라인| ≤ 10)
exact_topN           = file_hit AND (후보 중 하나라도 정답라인과 정확히 일치)
line_hit_strict_topN = line_hit_loose_topN AND cwe_ok(category, v1의 CWE)

실패 4종(§17-3): "잘못된 라인"만 "N개 후보 전부가 loose 실패"로 재정의, 나머지 3종은 §16-4 동일.

top-1(§16) 결과와 나란히 비교(§17-3 필수 요구): 특히 login.ts/search.ts strict 유지 여부.

실행: python rebuild/l1_score_topn.py juice-shop
출력: rebuild/out/l1_score_topn_juice-shop.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
sys.path.insert(0, str(ROOT))

from graph_spec_score_r2 import LINE_TOL, cwe_ok, load_truth  # noqa: E402

REGRESSION_WATCH_FILES = ("routes/login.ts", "routes/search.ts")  # §17-4 ②


def main(repo: str) -> None:
    truth_code, _truth_non = load_truth(repo)
    assert len(truth_code) == 36, f"코드 항목 {len(truth_code)} — 36 이어야 한다"

    s1_rows = [json.loads(l) for l in (OUT / f"repo_bench_{repo}_s1.jsonl").open()]
    v1_vuln_by_file = {r["file"]: r for r in s1_rows if r["label"] == "vuln"}
    v1_vuln_file_set = set(v1_vuln_by_file)

    topn_rows = [json.loads(l) for l in (OUT / f"l1_localize_topn_{repo}.jsonl").open()]
    topn_by_file = {r["file"]: r for r in topn_rows}

    top1_score = json.loads((OUT / f"l1_score_{repo}.json").read_text())
    top1_detail_by_id = {d["id"]: d for d in top1_score["detail"]}

    detail = []
    for t in truth_code:
        cat = t["category"]
        sink_file = t["sink_file"]
        file_hit = sink_file in v1_vuln_file_set
        rec = topn_by_file.get(sink_file)
        v1_cwe = v1_vuln_by_file.get(sink_file, {}).get("cwe", "")
        candidates = rec.get("l1_lines") if rec else None
        skip = bool(rec.get("skip_reason")) if rec else False
        candidates = candidates or []

        loose = bool(file_hit and any(
            abs(c - int(t["sink_line"])) <= LINE_TOL for c in candidates))
        exact = bool(file_hit and any(c == int(t["sink_line"]) for c in candidates))
        cwe_match = cwe_ok(cat, v1_cwe) if file_hit else False
        strict = loose and cwe_match

        if strict:
            failure = None
        elif not file_hit or skip or not candidates:
            failure = "localization_실패"
        elif not loose and not cwe_match:
            failure = "잘못된_라인"
        elif loose and not cwe_match:
            failure = "라인_맞고_CWE_틀림"
        else:
            failure = "CWE_맞고_라인_틀림"

        detail.append({
            "id": t["id"], "file": sink_file, "truth_line": t["sink_line"], "category": cat,
            "file_hit": file_hit, "v1_cwe": v1_cwe, "candidates": candidates,
            "loose": loose, "exact": exact, "strict": strict, "failure_class": failure,
            "top1_strict": top1_detail_by_id.get(t["id"], {}).get("strict"),
            "top1_loose": top1_detail_by_id.get(t["id"], {}).get("loose"),
        })

    denom = 36

    def count(pred):
        return sum(1 for d in detail if pred(d))

    loose_n = count(lambda d: d["loose"])
    strict_n = count(lambda d: d["strict"])
    exact_n = count(lambda d: d["exact"])

    loose_top1 = top1_score["line_hit_loose"]
    strict_top1 = top1_score["line_hit_strict"]

    # §17-4 회귀 감시: login.ts(3/3)·search.ts(2/2) strict 유지 여부
    watch = [d for d in detail if d["file"] in REGRESSION_WATCH_FILES]
    watch_strict_topn = sum(1 for d in watch if d["strict"])
    watch_strict_top1 = sum(1 for d in watch if d["top1_strict"])
    regression = watch_strict_topn < watch_strict_top1

    goal_c1 = loose_n > loose_top1
    goal_c2 = not regression
    if goal_c1 and goal_c2:
        verdict = "GOAL-MET"
    elif not goal_c1 and not regression:
        verdict = "PARTIAL"
    else:
        verdict = "NOT-MET" if (not goal_c1 and regression) else "PARTIAL"

    result = {
        "repo": repo, "denominator_items": denom, "n_candidates": 3,
        "line_hit_loose": loose_n, "line_hit_strict": strict_n, "exact_line": exact_n,
        "line_hit_loose_rate": round(loose_n / denom, 4),
        "line_hit_strict_rate": round(strict_n / denom, 4),
        "exact_line_rate": round(exact_n / denom, 4),
        "vs_top1": {
            "loose_top1": loose_top1, "loose_topn": loose_n, "delta_loose": loose_n - loose_top1,
            "strict_top1": strict_top1, "strict_topn": strict_n, "delta_strict": strict_n - strict_top1,
            "exact_top1": top1_score["exact_line"], "exact_topn": exact_n,
        },
        "regression_watch_§17-4": {
            "files": list(REGRESSION_WATCH_FILES),
            "strict_top1": watch_strict_top1, "strict_topn": watch_strict_topn,
            "regression": regression,
        },
        "failure_breakdown": {
            "localization_실패": count(lambda d: d["failure_class"] == "localization_실패"),
            "잘못된_라인": count(lambda d: d["failure_class"] == "잘못된_라인"),
            "라인_맞고_CWE_틀림": count(lambda d: d["failure_class"] == "라인_맞고_CWE_틀림"),
            "CWE_맞고_라인_틀림": count(lambda d: d["failure_class"] == "CWE_맞고_라인_틀림"),
        },
        "§17-4_판정": verdict,
        "판정_근거": {
            "①_loose_topN(>19)": f"{loose_n} > {loose_top1} = {goal_c1}",
            "②_회귀없음(login/search strict 유지)": f"top1={watch_strict_top1} topn={watch_strict_topn} → 회귀={regression}",
        },
        "detail": detail,
    }
    out_path = OUT / f"l1_score_topn_{repo}.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k != "detail"},
                      ensure_ascii=False, indent=2))
    print(f"\n저장: {out_path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "juice-shop")
