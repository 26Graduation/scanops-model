"""
ScanOps v3 — 점수 앙상블 (사양서 §6-C의 저비용판)
==================================================
여러 어댑터의 logprob 점수를 z-정규화 후 가중합해 하나의 연속 점수로 만든다.
가중치 w와 임계값 τ는 **tune split에서만** 고르고, 보고는 report split에서 한다(§3.4).

왜 다수결이 아니라 점수 합인가:
  다수결은 각 모델을 이미 이진화한 뒤 합치므로 정보를 버린다. 연속 점수를 합치면
  같은 비용(모델당 forward 1회)으로 더 나은 순위(AUC)를 얻을 수 있다.
  비용은 모델 수에 비례(2모델 = 2배), self-consistency k=5(5배)보다 싸다.

실행: python rebuild/ensemble_scores.py <base> <tagA> <tagB> [tagC...]
      예) python rebuild/ensemble_scores.py primevul v3_r16_s42 v1
출력: out/ensemble_{base}_{tags}.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from bench_common import pairwise_score, score
from sweep_threshold import auc, trivial_baseline

ROOT = Path(__file__).resolve().parent


def load(tag: str, split: str) -> dict[str, float]:
    """키: pair_id+label (없으면 순번). 같은 split이면 순서가 같으므로 인덱스로 맞춘다."""
    p = ROOT / "out" / f"{tag}_logprob_{split}.jsonl"
    return {i: json.loads(l)["score"] for i, l in enumerate(p.open())}


def metas(tag: str, split: str) -> list[dict]:
    p = ROOT / "out" / f"{tag}_logprob_{split}.jsonl"
    return [json.loads(l)["meta"] for l in p.open()]


def zscore(d: dict[int, float]) -> dict[int, float]:
    xs = list(d.values())
    m = sum(xs) / len(xs)
    sd = (sum((x - m) ** 2 for x in xs) / len(xs)) ** 0.5 or 1.0
    return {k: (v - m) / sd for k, v in d.items()}


def combine(scores: list[dict[int, float]], w: list[float]) -> list[float]:
    n = len(scores[0])
    return [sum(wi * s[i] for wi, s in zip(w, scores)) for i in range(n)]


def recs_from(vals: list[float], ms: list[dict]) -> list[dict]:
    return [{"meta": m, "score": v} for m, v in zip(ms, vals)]


def apply_tau(recs, tau):
    return [{"meta": r["meta"], "label": "vuln" if r["score"] >= tau else "safe"} for r in recs]


def best_point(recs, fpr_cap=0.35):
    ss = sorted({round(r["score"], 3) for r in recs})
    step = max(1, len(ss) // 200)
    cands = []
    for t in ss[::step] + [0.0]:
        s = score(apply_tau(recs, t)); s["tau"] = t
        cands.append(s)
    f1max = max(cands, key=lambda x: x["f1"])
    capped = max([c for c in cands if c["fpr"] <= fpr_cap] or cands, key=lambda x: x["f1"])
    return f1max, capped


def main() -> None:
    base, tags = sys.argv[1], sys.argv[2:]
    out = {"base": base, "tags": tags, "weights_grid": []}
    tune_s = [zscore(load(t, f"{base}_tune")) for t in tags]
    rep_s = [zscore(load(t, f"{base}_report")) for t in tags]
    tune_m, rep_m = metas(tags[0], f"{base}_tune"), metas(tags[0], f"{base}_report")

    # 가중치 그리드 (2모델 기준 0.0~1.0, 0.1 간격). 3모델 이상이면 균등가중만.
    grids = [[round(a, 1), round(1 - a, 1)] for a in [i / 10 for i in range(11)]] \
        if len(tags) == 2 else [[1 / len(tags)] * len(tags)]

    best = None
    for w in grids:
        tr = recs_from(combine(tune_s, w), tune_m)
        a = auc(tr)
        f1max, capped = best_point(tr)
        row = {"w": w, "auc_tune": a, "f1max_tune": f1max["f1"], "tau_f1max": f1max["tau"],
               "capped_f1_tune": capped["f1"], "tau_capped": capped["tau"],
               "capped_fpr_tune": capped["fpr"]}
        out["weights_grid"].append(row)
        # 선택 기준: FPR 제약 안에서의 F1 (전량양성 붕괴를 피하려고)
        if best is None or row["capped_f1_tune"] > best["capped_f1_tune"]:
            best = row

    rr = recs_from(combine(rep_s, best["w"]), rep_m)
    out["chosen"] = best
    out["report"] = {"auc": auc(rr),
                     "at_tau_capped": {**score(apply_tau(rr, best["tau_capped"])),
                                       "tau": best["tau_capped"]},
                     "at_tau_f1max": {**score(apply_tau(rr, best["tau_f1max"])),
                                      "tau": best["tau_f1max"]},
                     "trivial_all_vuln": trivial_baseline(rr)}
    if rep_m and "pair_id" in rep_m[0]:
        out["report"]["pairwise_at_tau_capped"] = pairwise_score(apply_tau(rr, best["tau_capped"]))
    # 단일 모델 대비 (앙상블이 실제로 이득인지)
    for t, s in zip(tags, rep_s):
        r1 = recs_from([s[i] for i in range(len(rep_m))], rep_m)
        f1max, capped = best_point(r1)
        out.setdefault("single_model_report", {})[t] = {
            "auc": auc(r1), "capped_f1": capped["f1"], "capped_fpr": capped["fpr"],
            "f1max": f1max["f1"]}
    p = ROOT / "out" / f"ensemble_{base}_{'_'.join(tags)}.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in out.items() if k != "weights_grid"},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
