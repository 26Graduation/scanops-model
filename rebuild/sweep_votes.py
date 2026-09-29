"""
ScanOps v3 — self-consistency 투표 임계 스윕 (사양서 §6-A)
==========================================================
eval_v3.py sample 모드가 남긴 표(votes)를 읽어 "vuln 표 t개 이상 → VULNERABLE"의 t를 스윕한다.
t는 tune에서 고르고 report에서 보고한다(§3.4). 비용(샘플 수·지연)도 함께 싣는다.

실행: python rebuild/sweep_votes.py <tag> <base> <k>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from bench_common import pairwise_score, score

ROOT = Path(__file__).resolve().parent


def load(tag: str, split: str, k: int) -> list[dict]:
    p = ROOT / "out" / f"{tag}_{split}_votes_k{k}.jsonl"
    return [json.loads(l) for l in p.open()] if p.exists() else []


def at_t(recs: list[dict], t: int) -> list[dict]:
    return [{"meta": r["meta"], "label": "vuln" if r["n_vuln_votes"] >= t else "safe"} for r in recs]


def main() -> None:
    tag, base, k = sys.argv[1], sys.argv[2], int(sys.argv[3])
    tune, report = load(tag, f"{base}_tune", k), load(tag, f"{base}_report", k)
    curve = []
    for t in range(1, k + 1):
        s = score(at_t(tune, t)); s["t"] = t
        curve.append(s)
    best = max(curve, key=lambda x: x["f1"])
    capped = max([c for c in curve if c["fpr"] <= 0.35] or curve, key=lambda x: x["f1"])
    res = {"tag": tag, "base": base, "k": k, "curve_tune": curve,
           "chosen_t_f1max": best["t"], "chosen_t_capped": capped["t"], "tune_capped": capped}
    if report:
        res["report_at_t_f1max"] = {**score(at_t(report, best["t"])), "t": best["t"]}
        res["report_at_t_capped"] = {**score(at_t(report, capped["t"])), "t": capped["t"]}
        if "pair_id" in report[0]["meta"]:
            res["report_pairwise_capped"] = pairwise_score(at_t(report, capped["t"]))
    (ROOT / "out" / f"{tag}_votes_sweep_{base}.json").write_text(
        json.dumps(res, ensure_ascii=False, indent=2))
    print(json.dumps(res, ensure_ascii=False, indent=2)[:2500])


if __name__ == "__main__":
    main()
