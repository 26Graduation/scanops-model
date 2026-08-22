"""L1 provenance 라인 단위 재계산 — GRAPH_RUN_SPEC.md §17-5.

기존(§12-3/R3/R4)의 provenance는 **파일 단위**였다: 그래프 finding이 v1이 vuln으로 찍은
"같은 파일"에 있으면 무조건 overlap, 아니면 graph-added(=graph-only)였다. v1은 파일만
찍고 라인을 못 내서 이렇게밖에 할 수 없었다(§16-3 배경).

이제 L1 top-N(§17)으로 v1의 라인 후보가 있으니, R4 최종 arm(F3 + verifier TRUE만,
`graph_spec_critic_r3_F3_juice-shop.json`)의 TRUE finding 중 실제 정답과 매치된 것만
골라 **라인 단위**로 다시 분류한다. graph/critic 은 재실행하지 않는다(§16-5 "R2~R4 결과 파일
수정 안 함" 원칙 유지 — 이 파일은 읽기만 한다).

분류 (파일별 L1 후보 유무에 따라 3가지):
  overlap        finding 라인이 v1 top-N 라인 후보 중 하나와 |diff| ≤ 10
  graph-only     v1이 그 파일을 아예 안 찍었거나(파일조차 다름), 찍었고 라인 후보도 있는데
                 전부 tol 밖 — 확신 있는 판정
  ambiguous      v1이 그 파일을 찍었는데 L1 top-N이 후보를 하나도 못 냄(41/115 중 하나) —
                 line-level로 확신 있게 못 가른다. graph-only로 뭉개지 않고 별도 집계한다.

실행: python rebuild/l1_provenance.py juice-shop
출력: rebuild/out/l1_provenance_juice-shop.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
sys.path.insert(0, str(ROOT))

import graph_spec_score_r2 as S  # noqa: E402

TOL = S.LINE_TOL
R4_CRITIC_PATH = OUT / "graph_spec_critic_r3_F3_juice-shop.json"


def main(repo: str) -> None:
    truth_code, _ = S.load_truth(repo)

    # ── v1 라인 후보 (L1 top-N, §17) ────────────────────────────────────────
    s1_rows = [json.loads(l) for l in (OUT / f"repo_bench_{repo}_s1.jsonl").open()]
    v1_vuln_files = {r["file"] for r in s1_rows if r["label"] == "vuln"}
    topn_rows = [json.loads(l) for l in (OUT / f"l1_localize_topn_{repo}.jsonl").open()]
    v1_lines_by_file = {r["file"]: r.get("l1_lines") or [] for r in topn_rows}

    def classify(file: str, line: int | None) -> str:
        if file not in v1_vuln_files:
            return "graph-only"  # v1이 이 파일 자체를 vuln으로 찍은 적 없음 — 확신 있음
        cands = v1_lines_by_file.get(file, [])
        if not cands:
            return "ambiguous"  # v1이 파일은 찍었으나 L1이 후보를 하나도 못 냄
        if line is not None and any(abs(line - c) <= TOL for c in cands):
            return "overlap"
        return "graph-only"  # v1이 파일도 찍고 후보도 냈는데 전부 tol 밖 — 확신 있는 graph-only

    # ── R4 최종 arm (읽기 전용, 재실행 안 함) ─────────────────────────────────
    d = json.loads(R4_CRITIC_PATH.read_text())
    true_graph = [
        {"file": f["file"], "line": f["line"], "cwe": f["cwe"], "category": None,
         "provenance_file_level": f["provenance"],
         "provenance_line_level": classify(f["file"], f["line"])}
        for f in d["findings"] if f["critic_verdict"] == "TRUE" and f["provenance"] != "v1-only"
    ]

    res = S.score(truth_code, true_graph)

    hit_detail = []
    graph_only_tp = 0
    ambiguous_tp = 0
    reclassified = []
    for x in res["detail"]:
        m = x["matched_strict"] or x["matched_loose"]
        if not m:
            continue
        old = m["provenance_file_level"]
        new = m["provenance_line_level"]
        if old != new:
            reclassified.append({"id": x["id"], "file": m["file"], "line": m["line"],
                                  "file_level_was": old, "line_level_now": new})
        if new == "graph-only":
            graph_only_tp += 1
        elif new == "ambiguous":
            ambiguous_tp += 1
        hit_detail.append({
            "id": x["id"], "file": m["file"], "line": m["line"], "truth_line": x["truth_line"],
            "strict": x["strict"], "loose": x["loose"],
            "provenance_file_level": old, "provenance_line_level": new,
        })

    old_condition_4 = 0  # §12-7④ 원 판정(파일 단위) — 이미 R4에서 0으로 확정, 재확인만
    for x in res["detail"]:
        m = x["matched_strict"] or x["matched_loose"]
        if m and m["provenance_file_level"] == "graph-added":
            old_condition_4 += 1

    result = {
        "repo": repo, "source_arm": str(R4_CRITIC_PATH), "note":
            "R4 그래프+critic 결과는 읽기만 했다 — 재실행하지 않았다(§16-5/§17-6).",
        "n_true_graph_findings": len(true_graph),
        "n_matched_truth_items": len(hit_detail),
        "graph_only_TP_line_level_§12-7④": graph_only_tp,
        "graph_only_TP_file_level_original": old_condition_4,
        "ambiguous_TP_no_l1_candidate": ambiguous_tp,
        "reclassified_file_to_line": reclassified,
        "판정_§12-7④_라인단위": "PASS" if graph_only_tp >= 1 else "FAIL (그대로, R4 결과 확정)",
        "hit_detail": hit_detail,
    }
    out_path = OUT / f"l1_provenance_{repo}.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k != "hit_detail"},
                      ensure_ascii=False, indent=2))
    print(f"\n저장: {out_path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "juice-shop")
