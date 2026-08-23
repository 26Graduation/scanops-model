"""PLAN.md 2단계 — 레포별 룰(§17-1단계) 재측정. 같은 채점기(`r4_cvefixes_pilot.py::score`) 재사용.

juice-shop G2는 재실행/재채점하지 않는다(PLAN.md 2단계 지시 그대로). 여기서 보는 건
외부 3레포(fittr-flickr/maps-js-icoads/jquery-ui)를 **레포별 LLM 스펙(S2B/S2C)**으로 돌린
`graph_spec_run.py` 결과뿐이다 — R4 STEP7 파일럿(spec_G2_juice-shop.tsv 재사용, 0/13)과는
스펙 출처가 다르다.

실행: python rebuild/ext_repo_score.py
출력: rebuild/out/ext_repo_score.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
DATA = ROOT / "data" / "repo_bench"
sys.path.insert(0, str(ROOT))

from r4_cvefixes_pilot import score  # noqa: E402 — 채점기 재사용, 재정의하지 않는다

REPOS = {
    "dpup/fittr-flickr": "fittr-flickr",
    "saxman/maps-js-icoads": "maps-js-icoads",
    "jquery/jquery-ui": "jquery-ui",
    "tojocky/node-printer": "node-printer",
    "gperson/angular-test-reporter": "angular-test-reporter",
    "Atinux/schema-inspector": "schema-inspector",
    "christian-bromann/rgb2hex": "rgb2hex",
    "flitto/express-param": "express-param",
    "vercel/ms": "ms",
    "jonschlinkert/assign-deep": "assign-deep",
    "jonschlinkert/merge-deep": "merge-deep",
}
ARMS = ["S2B", "S2C"]


def load_findings(repo_short: str, arm: str) -> tuple[list[dict], int]:
    d = json.loads((OUT / f"graph_spec_arm_{arm}_{repo_short}.json").read_text())
    res = d.get("result") or {}
    fi = [x for x in res.get("findings", []) if not x.get("sanitized")]
    return fi, d["n_files"]


def main() -> None:
    truth_all = [json.loads(l) for l in (DATA / "cvefixes_linetruth_r4.jsonl").open()]
    out = {"pilot_baseline_note":
           "R4 STEP7 파일럿(spec_G2_juice-shop.tsv 재사용)은 0/13이었다 "
           "(rebuild/out/r4_cvefixes_pilot_juice-shop_scorer.json). 이번은 그 대신 레포별 "
           "LLM 스펙(1단계, graph_spec_llm.py)으로 돌린 결과다.",
           "repos": {}}

    for repo_full, repo_short in REPOS.items():
        rows = [t for t in truth_all if t["repo"] == repo_full]
        entry = {"n_truth_lines": len(rows), "arms": {}}
        for arm in ARMS:
            fi, n_files = load_findings(repo_short, arm)
            s = score(rows, fi, n_files)
            entry["arms"][arm] = {k: v for k, v in s.items() if k != "detail"}
            entry["arms"][arm]["detail"] = s["detail"]
            print(f"{repo_full:28s} {arm}  strict {s['strict_정답라인']}/{s['denominator_정답라인']}  "
                  f"loose {s['loose_정답라인']}  exact {s['exact_line_정답라인']}  "
                  f"file_reached {s['file_reached_정답라인']}  경보 {s['경보건수']}")
        out["repos"][repo_full] = entry

    # 합계 (pilot 0/13과 직접 비교 가능한 단위)
    for arm in ARMS:
        tot_denom = sum(e["n_truth_lines"] for e in out["repos"].values())
        tot_strict = sum(e["arms"][arm]["strict_정답라인"] for e in out["repos"].values())
        tot_loose = sum(e["arms"][arm]["loose_정답라인"] for e in out["repos"].values())
        tot_exact = sum(e["arms"][arm]["exact_line_정답라인"] for e in out["repos"].values())
        tot_reached = sum(e["arms"][arm]["file_reached_정답라인"] for e in out["repos"].values())
        out[f"total_{arm}"] = {"denom": tot_denom, "strict": tot_strict, "loose": tot_loose,
                                "exact": tot_exact, "file_reached": tot_reached}
        print(f"\n[합계 {arm}] strict {tot_strict}/{tot_denom}  loose {tot_loose}  "
              f"exact {tot_exact}  file_reached(경로는 지남) {tot_reached}")

    (OUT / "ext_repo_score.json").write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"\n저장: {OUT / 'ext_repo_score.json'}")


if __name__ == "__main__":
    main()
