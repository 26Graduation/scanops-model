"""Phase B-3 / B-4 — 레포 벤치 채점과 사전등록 판정.

arm:
  S1  ScanOps-LLM            (repo_bench_{repo}_s1.jsonl)
  S2  ScanOps-Full           S1 ∪ code_graph(vuln) ∪ multi_graph(vuln) ∪ Joern(vuln)
                             — **vuln 만 더한다. safe/unknown 은 어떤 판정도 덮지 않는다**
                               (ABLATION_RESULTS.md: graph safe 42.5% 오판)
  C1  Claude-File PARITY     (repo_bench_{repo}_c1_parity.jsonl)
  C2  Claude-File STRONG     (있을 때만)

매칭은 **파일 단위**(사양 §6-d, §11 S-1). 두 가지 recall 을 낸다:
  loc      정답의 sink_file 을 vuln 으로 판정했는가            ← 주지표
  loc+cat  위 + 카테고리 일치(category_map.json)               ← 부지표

출력: rebuild/out/repo_bench_{repo}_metrics.json
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
DATA = ROOT / "data" / "repo_bench"
BOOT = 2000
SEED = 42


def load_jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.open()] if p.exists() else []


def boot_ci(hits: list[int], n_boot: int = BOOT) -> tuple[float, float]:
    """비율의 부트스트랩 95% CI (항목 재표집)."""
    if not hits:
        return (0.0, 0.0)
    rng = random.Random(SEED)
    n = len(hits)
    vals = []
    for _ in range(n_boot):
        s = sum(hits[rng.randrange(n)] for _ in range(n))
        vals.append(s / n)
    vals.sort()
    return (round(vals[int(0.025 * n_boot)], 4), round(vals[int(0.975 * n_boot)], 4))


def main(repo: str) -> None:
    truth_all = load_jsonl(DATA / f"{repo}_truth.jsonl")
    inv = json.loads((OUT / f"repo_bench_{repo}_inventory.json").read_text())
    cat_map = json.loads((DATA / "category_map.json").read_text())

    scanned = set(inv["truth_files_in_scope"])          # 정답이 있는 범위 내 파일
    s1 = {r["file"]: r for r in load_jsonl(OUT / f"repo_bench_{repo}_s1.jsonl")}
    c1 = {r["file"]: r for r in load_jsonl(OUT / f"repo_bench_{repo}_c1_parity.jsonl")}
    c2 = {r["file"]: r for r in load_jsonl(OUT / f"repo_bench_{repo}_c2_strong.jsonl")}
    all_files = sorted(set(s1) | set(c1))

    truth = [t for t in truth_all if t["sink_file"] in set(inv["truth_files_in_scope"])
             and t["confidence"] in ("high", "med")]
    truth_files = {t["sink_file"] for t in truth}

    # ── 그래프 성분 ──────────────────────────────────────────────────────────
    g = {}
    gp = OUT / f"repo_bench_{repo}_graph.json"
    if gp.exists():
        g = json.loads(gp.read_text())
    cg_vuln = set(g.get("code_graph_vuln_files", []))
    mg_vuln = set(g.get("multi_graph_vuln_files", []))
    jo_vuln: set[str] = set()
    jp = OUT / f"repo_bench_{repo}_joern.json"
    joern_meta = {}
    if jp.exists():
        j = json.loads(jp.read_text())
        joern_meta = {k: j.get(k) for k in
                      ("elapsed_seconds", "timed_out", "returncode", "mode",
                       "fallback_partial_graph", "verdict_counts")}
        jo_vuln = set(j.get("vuln_files", []) or [])

    def cat_ok(truth_cat: str, cwe: str) -> bool:
        allow = cat_map.get(truth_cat)
        if not allow:
            return False
        if allow == ["*"]:
            return True
        return any(cwe.upper().startswith(a) for a in allow)

    def arm_files(name: str) -> tuple[set[str], dict[str, str]]:
        """(vuln 판정 파일 집합, 파일→CWE)."""
        if name == "S1":
            v = {f for f, r in s1.items() if r["label"] == "vuln"}
            return v, {f: s1[f].get("cwe", "") for f in v}
        if name == "S2":
            v = {f for f, r in s1.items() if r["label"] == "vuln"} | cg_vuln | mg_vuln | jo_vuln
            cw = {}
            for f in v:
                cw[f] = (s1.get(f, {}).get("cwe", "")
                         or (g.get("multi_graph_verdicts", {}).get(f, {}) or {}).get("category", ""))
            return v, cw
        if name == "C1":
            v = {f for f, r in c1.items() if r["label"] == "vuln"}
            return v, {f: c1[f].get("cwe", "") for f in v}
        if name == "C2":
            v = {f for f, r in c2.items() if r["label"] == "vuln"}
            return v, {f: c2[f].get("cwe", "") for f in v}
        raise KeyError(name)

    arms = ["S1", "S2", "C1"] + (["C2"] if c2 else [])
    report: dict = {
        "repo": repo,
        "n_files_scanned": len(all_files),
        "truth_total": len(truth_all),
        "truth_in_scope_scored": len(truth),
        "truth_out_of_scope": inv["truth_out_of_scope"],
        "truth_out_of_scope_note": ("스캔 범위 밖(.yml/.tf/docker-compose/.sol) — "
                                    "세 arm 모두 자동 미탐. recall 분모에서 뺐다."),
        "PRECISION_CAVEAT": (
            "**precision 과 오탐 수를 절대값으로 읽지 말 것.** 정답표는 juice-shop 챌린지 중 "
            "소스에 `vuln-code-snippet vuln-line` 마커가 있는 것만 담는다(9개 파일). "
            "juice-shop 은 의도적으로 취약한 앱이고 마커 없는 취약점이 더 많다 → "
            "여기서 '오탐'으로 센 것 중 상당수가 실제 취약점일 수 있다. "
            "따라서 **오탐 수는 상한, precision 은 하한**이다. "
            "해석 가능한 것은 (a) 같은 정답표로 잰 **recall**, (b) 같은 파일 집합에서의 "
            "**arm 간 상대적 경보율(flag_rate)** 뿐이다."),
        "n_cross_file": sum(1 for t in truth if t["cross_file"]),
        "n_single_file": sum(1 for t in truth if not t["cross_file"]),
        "graph_components": {
            "code_graph_vuln_files": sorted(cg_vuln),
            "multi_graph_vuln_files": sorted(mg_vuln),
            "joern_vuln_files": sorted(jo_vuln),
            "code_graph_seconds": g.get("code_graph_seconds"),
            "multi_graph_seconds": g.get("multi_graph_seconds"),
            "joern": joern_meta,
        },
        "arms": {},
    }

    for a in arms:
        v, cw = arm_files(a)
        hits_loc = [1 if t["sink_file"] in v else 0 for t in truth]
        hits_cat = [1 if (t["sink_file"] in v and cat_ok(t["category"], cw.get(t["sink_file"], "")))
                    else 0 for t in truth]
        cf = [i for i, t in enumerate(truth) if t["cross_file"]]
        sf = [i for i, t in enumerate(truth) if not t["cross_file"]]
        fp_files = sorted(v - truth_files)
        tp_files = sorted(v & truth_files)
        elapsed = sum(r.get("elapsed", 0) for r in s1.values()) if a in ("S1", "S2") else None
        report["arms"][a] = {
            "n_vuln_files": len(v),
            "flag_rate": round(len(v) / len(all_files), 4),
            "recall_loc": round(sum(hits_loc) / len(truth), 4),
            "recall_loc_ci": boot_ci(hits_loc),
            "recall_loc_cross_file": round(sum(hits_loc[i] for i in cf) / len(cf), 4) if cf else None,
            "recall_loc_cross_file_ci": boot_ci([hits_loc[i] for i in cf]) if cf else None,
            "recall_loc_single_file": round(sum(hits_loc[i] for i in sf) / len(sf), 4) if sf else None,
            "recall_cat": round(sum(hits_cat) / len(truth), 4),
            "recall_cat_ci": boot_ci(hits_cat),
            "n_fp_files": len(fp_files),
            "fp_per_file": round(len(fp_files) / len(all_files), 4),
            "precision_file": round(len(tp_files) / len(v), 4) if v else 0.0,
            "tp_files": tp_files,
            "fp_files_sample": fp_files[:15],
            "scan_seconds": round(elapsed, 1) if elapsed else None,
        }

    # ── B-4 판정 (사전등록 §6-e) ────────────────────────────────────────────
    s2, c1a = report["arms"]["S2"], report["arms"]["C1"]
    d = (s2["recall_loc_cross_file"] or 0) - (c1a["recall_loc_cross_file"] or 0)
    ci_overlap = not (s2["recall_loc_cross_file_ci"][0] > c1a["recall_loc_cross_file_ci"][1]
                      or c1a["recall_loc_cross_file_ci"][0] > s2["recall_loc_cross_file_ci"][1])
    fp_ok = (s2["fp_per_file"] <= c1a["fp_per_file"]) or (s2["precision_file"] >= c1a["precision_file"])
    if d >= 0.20 and fp_ok:
        verdict = "GRAPH-WIN"
    elif d < 0:
        verdict = "GRAPH-LOSE"
    else:
        verdict = "GRAPH-TIE"
    if d >= 0.20 and not fp_ok:
        verdict = "GRAPH-TIE"     # 조건 ② 미충족 → WIN 아님
    if ci_overlap and verdict == "GRAPH-WIN":
        verdict = "GRAPH-TIE"

    # ── 포화 진단: recall 이 arm 을 가르지 못하면 그 사실을 먼저 적는다 ────────
    recalls = {a: report["arms"][a]["recall_loc"] for a in arms}
    saturated = len(set(round(v, 4) for v in recalls.values())) == 1
    report["SATURATION"] = {
        "recall_identical_across_arms": saturated,
        "recall_by_arm": recalls,
        "flag_rate_by_arm": {a: report["arms"][a]["flag_rate"] for a in arms},
        "verdict": ("**이 벤치는 포화됐다 — recall 이 arm 을 가르지 못한다.**" if saturated
                    else "recall 이 arm 을 가른다"),
        "why": ("정답이 있는 파일이 9개뿐인데 세 arm 모두 전체 파일의 45~62% 를 vuln 으로 판정한다. "
                "파일 단위 매칭에서는 그 9개가 자동으로 전부 포함된다 → recall 이 1.0 으로 붙는다. "
                "**사전등록한 설계의 결함이고, 결과를 본 뒤 지표를 바꾸지 않는다.** "
                "대신 이 벤치가 실제로 가르는 것만 읽는다: (a) **arm 간 경보율**, "
                "(b) **S2 − S1 = 그래프가 새로 잡은 정답 수와 추가로 켠 경보 수**, "
                "(c) 카테고리까지 맞힌 비율(recall_cat)."),
    }

    enough = (report["truth_in_scope_scored"] >= 40 and report["n_cross_file"] >= 12)
    report["gate_sample_size"] = {
        "truth_scored": report["truth_in_scope_scored"], "need": 40,
        "cross_file": report["n_cross_file"], "need_cross_file": 12,
        "pass": enough,
        "note": ("정답 44건 중 스캔 범위 내 33건만 채점한다 → 사전등록 '합계 ≥ 40' 미달. "
                 "사양 §6-b 대로 **표본 부족**으로 적고, GRAPH 판정은 참고값으로만 싣는다."
                 if not enough else ""),
    }
    report["graph_verdict"] = {
        "verdict": verdict,
        "binding": enough,
        "delta_cross_file_recall_S2_minus_C1": round(d, 4),
        "threshold": 0.20,
        "fp_condition_met": fp_ok,
        "ci_overlap": ci_overlap,
        "S2_minus_S1_recall_loc": round(s2["recall_loc"] - report["arms"]["S1"]["recall_loc"], 4),
        "S2_minus_S1_recall_cross_file": round(
            (s2["recall_loc_cross_file"] or 0)
            - (report["arms"]["S1"]["recall_loc_cross_file"] or 0), 4),
        "S2_minus_S1_new_truth_files": sorted(
            set(arm_files("S2")[0] & truth_files) - set(arm_files("S1")[0] & truth_files)),
        "S2_minus_S1_extra_flagged_files": len(arm_files("S2")[0] - arm_files("S1")[0]),
        "presentation_wording": ("멀티파일 taint 주력 탐지기 + LLM 단건 주력"
                                 if verdict == "GRAPH-WIN" and enough
                                 else "보조 탐지 + 근거 표시"),
    }

    p = OUT / f"repo_bench_{repo}_metrics.json"
    p.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in report.items() if k != "graph_components"},
                     ensure_ascii=False, indent=2))
    print(f"저장: {p}")


if __name__ == "__main__":
    main(sys.argv[1])
