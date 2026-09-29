"""Phase 3-a — OWASP 110건을 진단 55 / 홀드아웃 55 로 나눈다 (사전 등록).

[사전 등록 — 분할 전 확정]
  · seed 42, 라벨 균형(각 split 에 vuln/safe 를 같은 수로)
  · 홀드아웃은 Phase 3-d 전까지 **열지 않는다** (패턴 튜닝에 쓰지 않는다)
  · 카테고리는 @WebServlet 경로에서 추출한다 (파일에 카테고리 라벨이 없다 — 실측)
  · 홀드아웃 판정 기준: IMPROVED = FPR ≤ 0.50 AND recall ≥ 0.75. 아니면 NOT-IMPROVED.

출력: rebuild/out/owasp_split_fix.json  {diagnostic:[idx...], holdout:[idx...]}
"""
from __future__ import annotations

import json
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "rebuild" / "out"
SEED = 42

# OWASP Benchmark 는 @WebServlet("/<category>-XX/BenchmarkTestNNNNN") 형태로
# 카테고리를 경로에 담는다. 파일 자체에는 카테고리 필드가 없다.
_WEBSERVLET = re.compile(r'@WebServlet\(\s*value\s*=\s*"?/?([a-zA-Z0-9_]+)', re.I)
_WEBSERVLET2 = re.compile(r'@WebServlet\(\s*"?/?([a-zA-Z0-9_]+)', re.I)


def category_of(code: str) -> str:
    for rx in (_WEBSERVLET, _WEBSERVLET2):
        m = rx.search(code)
        if m:
            return m.group(1).split("-")[0].lower()
    return "unknown"


def main() -> int:
    rows = [json.loads(l) for l in (ROOT / "data" / "owasp_holdout_bench.jsonl").open()]
    for i, r in enumerate(rows):
        r["_idx"] = i
        r["_cat"] = category_of(r["code"])

    rng = random.Random(SEED)
    diag, hold = [], []
    for label in ("vuln", "safe"):
        pool = sorted([r["_idx"] for r in rows if r["label"] == label])
        rng.shuffle(pool)
        half = len(pool) // 2
        diag += pool[:half]
        hold += pool[half:]

    import collections
    cats = collections.Counter(r["_cat"] for r in rows)
    res = {
        "seed": SEED,
        "diagnostic": sorted(diag), "holdout": sorted(hold),
        "n_diag": len(diag), "n_hold": len(hold),
        "diag_label": dict(collections.Counter(rows[i]["label"] for i in diag)),
        "hold_label": dict(collections.Counter(rows[i]["label"] for i in hold)),
        "category_dist_all": dict(cats),
        "gate": {"IMPROVED": "FPR <= 0.50 AND recall >= 0.75",
                 "else": "NOT-IMPROVED — 패턴 유지, 결과 그대로 기록"},
    }
    (OUT / "owasp_split_fix.json").write_text(json.dumps(res, indent=2, ensure_ascii=False))
    print(json.dumps({k: v for k, v in res.items()
                      if k not in ("diagnostic", "holdout")}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
