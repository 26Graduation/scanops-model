"""
ScanOps v3 — 부트스트랩 신뢰구간 (리포트 §7 "남은 한계"용)
==========================================================
F1 0.805 → 0.806 같은 차이를 "개선"이라고 쓰면 안 된다. 표본 크기에서 나오는
잡음 폭을 먼저 재고, 그 폭보다 작은 차이는 리포트에 "구분 불가"로 적는다.

방식: 케이스 단위 재표집(쌍 데이터는 쌍 단위로 재표집해야 독립성이 유지된다) 2,000회.
실행: python rebuild/bootstrap_ci.py <predictions.jsonl> [<비교대상.jsonl>]
"""
from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

from bench_common import score


def load(p: str) -> list[dict]:
    return [json.loads(l) for l in Path(p).open()]


def units(items: list[dict]) -> list[list[dict]]:
    """쌍 데이터는 쌍째로 재표집 — 같은 커밋의 두 샘플은 독립이 아니다."""
    if items and items[0]["meta"].get("pair_id"):
        g = defaultdict(list)
        for r in items:
            g[r["meta"]["pair_id"]].append(r)
        return list(g.values())
    return [[r] for r in items]


def boot(items: list[dict], n: int = 2000, seed: int = 0) -> dict:
    us = units(items)
    rng = random.Random(seed)
    f1s, recs, fprs = [], [], []
    for _ in range(n):
        samp = [x for _ in range(len(us)) for x in rng.choice(us)]
        s = score(samp)
        f1s.append(s["f1"]); recs.append(s["recall"]); fprs.append(s["fpr"])
    f1s.sort(); recs.sort(); fprs.sort()
    lo, hi = int(n * 0.025), int(n * 0.975)
    return {"f1": score(items)["f1"], "f1_ci95": [round(f1s[lo], 4), round(f1s[hi], 4)],
            "recall_ci95": [round(recs[lo], 4), round(recs[hi], 4)],
            "fpr_ci95": [round(fprs[lo], 4), round(fprs[hi], 4)]}


def paired_delta(a: list[dict], b: list[dict], n: int = 2000, seed: int = 0) -> dict:
    """같은 재표집에 두 시스템을 함께 태워 ΔF1의 분포를 본다(대응 표본)."""
    ua, ub = units(a), units(b)
    assert len(ua) == len(ub), "두 예측 파일의 케이스 수가 다르다"
    rng = random.Random(seed)
    ds = []
    for _ in range(n):
        idx = [rng.randrange(len(ua)) for _ in range(len(ua))]
        sa = [x for i in idx for x in ua[i]]
        sb = [x for i in idx for x in ub[i]]
        ds.append(score(sa)["f1"] - score(sb)["f1"])
    ds.sort()
    lo, hi = ds[int(n * 0.025)], ds[int(n * 0.975)]
    return {"delta_f1": round(score(a)["f1"] - score(b)["f1"], 4),
            "delta_ci95": [round(lo, 4), round(hi, 4)],
            "significant": bool(lo > 0 or hi < 0)}


if __name__ == "__main__":
    a = load(sys.argv[1])
    print(json.dumps(boot(a), ensure_ascii=False))
    if len(sys.argv) > 2:
        print(json.dumps(paired_delta(a, load(sys.argv[2])), ensure_ascii=False))
