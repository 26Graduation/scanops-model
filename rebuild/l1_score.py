"""L1 채점 — GRAPH_RUN_SPEC.md §16-4. 측정 전 확정된 정의를 그대로 구현한다.

§12-1 층 분류·§12-2 CWE 매핑·LINE_TOL=10 은 `graph_spec_score_r2.py` 걸 그대로 재사용한다
(새 규칙 만들지 않는다).

file_hit        = 정답 항목의 sink_file ∈ v1 vuln 파일 집합
line_hit_loose  = file_hit AND L1 라인 파싱 성공 AND |L1라인 − 정답라인| ≤ 10
exact_line      = file_hit AND L1 라인 == 정답라인
line_hit_strict = line_hit_loose AND cwe_ok(category, v1의 CWE)

실패 4종 (상호 배타, line_hit_strict 성공 건은 제외):
  localization_실패     file_hit False, 또는 file_hit인데 라인 파싱 실패/컨텍스트 초과
  잘못된_라인            file_hit, 라인 있음, loose False AND cwe_ok False
  라인_맞고_CWE_틀림      loose True, cwe_ok False
  CWE_맞고_라인_틀림      loose False, cwe_ok True

실행: python rebuild/l1_score.py juice-shop
출력: rebuild/out/l1_score_juice-shop.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
DATA = ROOT / "data" / "repo_bench"
sys.path.insert(0, str(ROOT))

from graph_spec_score_r2 import LINE_TOL, cwe_ok, load_truth  # noqa: E402


def main(repo: str) -> None:
    truth_code, _truth_non = load_truth(repo)
    assert len(truth_code) == 36, f"코드 항목 {len(truth_code)} — 36 이어야 한다"

    s1_rows = [json.loads(l) for l in (OUT / f"repo_bench_{repo}_s1.jsonl").open()]
    v1_vuln_by_file = {r["file"]: r for r in s1_rows if r["label"] == "vuln"}
    v1_vuln_file_set = set(v1_vuln_by_file)

    l1_path = OUT / f"l1_localize_{repo}.jsonl"
    l1_rows = [json.loads(l) for l in l1_path.open()]
    l1_by_file = {r["file"]: r for r in l1_rows}

    skipped = [r for r in l1_rows if r.get("skip_reason")]
    answered = [r for r in l1_rows if not r.get("skip_reason")]

    detail = []
    for t in truth_code:
        cat = t["category"]
        sink_file = t["sink_file"]
        file_hit = sink_file in v1_vuln_file_set
        l1_rec = l1_by_file.get(sink_file)
        v1_cwe = v1_vuln_by_file.get(sink_file, {}).get("cwe", "")

        l1_line_raw = l1_rec.get("l1_line") if l1_rec else None
        l1_skip = bool(l1_rec.get("skip_reason")) if l1_rec else False
        # LINE: 0 은 v2 SAFE 관례와 동일하게 "특정 라인 없음"으로 취급한다 — 우연한 ±10 매치를 막는다.
        l1_line = l1_line_raw if (l1_line_raw and l1_line_raw > 0) else None

        loose = bool(file_hit and l1_line is not None
                     and abs(l1_line - int(t["sink_line"])) <= LINE_TOL)
        exact = bool(file_hit and l1_line is not None and l1_line == int(t["sink_line"]))
        cwe_match = cwe_ok(cat, v1_cwe) if file_hit else False
        strict = loose and cwe_match

        if strict:
            failure = None
        elif not file_hit or l1_skip or l1_line is None:
            failure = "localization_실패"
        elif not loose and not cwe_match:
            failure = "잘못된_라인"
        elif loose and not cwe_match:
            failure = "라인_맞고_CWE_틀림"
        else:  # not loose and cwe_match
            failure = "CWE_맞고_라인_틀림"

        detail.append({
            "id": t["id"], "file": sink_file, "truth_line": t["sink_line"], "category": cat,
            "file_hit": file_hit, "v1_cwe": v1_cwe,
            "l1_line_raw": l1_line_raw, "l1_line_used": l1_line, "l1_skip_reason":
                l1_rec.get("skip_reason") if l1_rec else ("no_l1_record" if not file_hit else "missing"),
            "loose": loose, "exact": exact, "strict": strict, "failure_class": failure,
        })

    denom = 36
    n_files_unique = len({t["sink_file"] for t in truth_code})
    n_files_hit = len({d["file"] for d in detail if d["file_hit"]})

    def count(pred):
        return sum(1 for d in detail if pred(d))

    result = {
        "repo": repo, "denominator_items": denom,
        "unique_truth_files": n_files_unique,
        "file_hit_items": count(lambda d: d["file_hit"]),
        "file_hit_files": n_files_hit,
        "file_hit_rate_items": round(count(lambda d: d["file_hit"]) / denom, 4),
        "file_hit_rate_files": round(n_files_hit / n_files_unique, 4) if n_files_unique else 0.0,
        "line_hit_loose": count(lambda d: d["loose"]),
        "line_hit_strict": count(lambda d: d["strict"]),
        "exact_line": count(lambda d: d["exact"]),
        "line_hit_loose_rate": round(count(lambda d: d["loose"]) / denom, 4),
        "line_hit_strict_rate": round(count(lambda d: d["strict"]) / denom, 4),
        "exact_line_rate": round(count(lambda d: d["exact"]) / denom, 4),
        "failure_breakdown": {
            "localization_실패": count(lambda d: d["failure_class"] == "localization_실패"),
            "잘못된_라인": count(lambda d: d["failure_class"] == "잘못된_라인"),
            "라인_맞고_CWE_틀림": count(lambda d: d["failure_class"] == "라인_맞고_CWE_틀림"),
            "CWE_맞고_라인_틀림": count(lambda d: d["failure_class"] == "CWE_맞고_라인_틀림"),
        },
        "l1_calls": {
            "n_vuln_files_v1": len(v1_vuln_file_set),
            "n_answered": len(answered),
            "n_skipped": len(skipped),
            "skip_reasons": [{"file": r["file"], "reason": r["skip_reason"]} for r in skipped],
            "n_parsed_line_0_or_none": sum(
                1 for r in answered if not r.get("l1_line") or r.get("l1_line") == 0),
        },
        "detail": detail,
    }
    out_path = OUT / f"l1_score_{repo}.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k != "detail"},
                      ensure_ascii=False, indent=2))
    print(f"\n저장: {out_path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "juice-shop")
