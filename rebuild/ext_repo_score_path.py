"""PLAN.md 3단계 — 경로 기반 채점 추가. GRAPH_RUN_SPEC.md §18.

탐지 로직 재실행 없음. `graph_spec_arm_{S2B,S2C}_{repo}.json`(2단계 산출물)을 그대로 읽는다.
`r4_cvefixes_pilot.py::score()`(exact/near/strict)는 그대로 재사용하고, path_hit만 새로 추가한다.

실행: python rebuild/ext_repo_score_path.py
출력: rebuild/out/ext_repo_score_path.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
DATA = ROOT / "data" / "repo_bench"
sys.path.insert(0, str(ROOT))

from r4_cvefixes_pilot import score  # noqa: E402 — exact/near(loose)/strict 재사용
from ext_repo_score import REPOS, ARMS, load_findings  # noqa: E402

TOL = 10


def path_hit_for(rows: list[dict], findings: list[dict]) -> dict[str, bool]:
    """정답 항목 id -> path_hit 여부. §18-2: file+line 정확 일치, finding 자체 sink 줄 무관."""
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)
    out = {}
    for t in rows:
        cands = by_file.get(t["sink_file"], [])
        hit = any(
            node.get("file") == t["sink_file"] and node.get("line") == t["sink_line"]
            for f in cands for node in (f.get("path") or [])
        )
        out[t["id"]] = hit
    return out


def tier(exact: bool, path_hit: bool, near: bool) -> str:
    if exact:
        return "exact"
    if path_hit:
        return "path_hit"
    if near:
        return "near"
    return "miss"


def main() -> None:
    truth_all = [json.loads(l) for l in (DATA / "cvefixes_linetruth_r4.jsonl").open()]
    out = {"note": "탐지 재실행 안 함. 2단계(graph_spec_arm_*) 결과를 그대로 재채점.",
           "repos": {}}

    grand = {arm: {"denom": 0, "exact": 0, "path_hit": 0, "near": 0, "strict": 0, "miss": 0}
             for arm in ARMS}

    for repo_full, repo_short in REPOS.items():
        rows = [t for t in truth_all if t["repo"] == repo_full]
        entry = {"n_truth_lines": len(rows), "arms": {}}
        for arm in ARMS:
            fi, n_files = load_findings(repo_short, arm)
            base = score(rows, fi, n_files)  # exact / loose(near) / strict / 경보건수 등
            ph = path_hit_for(rows, fi)

            detail = []
            n_exact = n_near = n_strict = n_path = n_miss = 0
            for d in base["detail"]:
                exact = bool(d["exact"])
                near = bool(d["loose"])
                strict = bool(d["strict"])
                phit = ph.get(d["id"], False)
                t = tier(exact, phit, near)
                if exact:
                    n_exact += 1
                if near:
                    n_near += 1
                if strict:
                    n_strict += 1
                if phit:
                    n_path += 1
                if t == "miss":
                    n_miss += 1
                detail.append({**d, "path_hit": phit, "tier": t})

            entry["arms"][arm] = {
                "denom": len(rows), "exact": n_exact, "near": n_near, "strict": n_strict,
                "path_hit": n_path, "miss": n_miss, "raw_alarms": base["경보건수"],
                "detail": detail,
            }
            g = grand[arm]
            g["denom"] += len(rows); g["exact"] += n_exact; g["path_hit"] += n_path
            g["near"] += n_near; g["strict"] += n_strict; g["miss"] += n_miss

            print(f"{repo_full:28s} {arm}  exact {n_exact}  path_hit {n_path}  "
                  f"near {n_near}  strict {n_strict}  miss {n_miss}  "
                  f"raw_alarms {base['경보건수']}")
        out["repos"][repo_full] = entry

    out["grand_total"] = grand
    for arm in ARMS:
        g = grand[arm]
        print(f"\n[합계 {arm}] denom {g['denom']}  exact {g['exact']}  path_hit {g['path_hit']}  "
              f"near {g['near']}  strict {g['strict']}  miss {g['miss']}")

    (OUT / "ext_repo_score_path.json").write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"\n저장: {OUT / 'ext_repo_score_path.json'}")


if __name__ == "__main__":
    main()
