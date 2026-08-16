"""
길이 기준선 — AUC 의 자명 기준선을 0.5 가 아니라 **"길이만 쓰는 분류기"** 로 잡는다
=====================================================================================
지금까지 AUC 의 자명 기준선을 0.5(무작위)로 적었다. 그런데 이 벤치들에는
**취약 코드가 안전 코드보다 짧은 경향**이 있다. 그러면 "짧을수록 취약"이라고만 답해도
AUC 가 0.5 를 넘는다. **그 값을 재서 병기해야 모델의 기여분을 제대로 읽는다.**

재는 것:
  1. `ρ(score, 코드 길이)` 와 `ρ(gold, 코드 길이)` — 모델이 길이를 라벨보다 더 세게 쓰는가
  2. **길이만 쓰는 분류기의 AUC** (`score = −len(code)`) vs 모델 AUC

비용 $0. 실행: python3 rebuild/length_baseline.py [tag]
출력: out/length_baseline_{tag}.json
"""
from __future__ import annotations

import json
import re
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from sweep_threshold import auc  # noqa: E402

TAG = sys.argv[1] if len(sys.argv) > 1 else "v1"
CODE = re.compile(r"```[^\n]*\n(.*?)\n```", re.S)
SPLITS = [("test", "내부 test"), ("cleanvul_v2_report", "CleanVul_v2 report"),
          ("primevul_report", "PrimeVul report"), ("cvefixes157", "CVEfixes 157"),
          ("cybernative154", "CyberNative 154")]


def spearman(a: list[float], b: list[float]) -> float:
    def rk(xs):
        o = sorted(range(len(xs)), key=lambda i: xs[i])
        r = [0.0] * len(xs)
        for p, i in enumerate(o):
            r[i] = p
        return r
    ra, rb = rk(a), rk(b)
    n = len(a)
    ma, mb = sum(ra) / n, sum(rb) / n
    cov = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    va = sum((x - ma) ** 2 for x in ra) ** 0.5
    vb = sum((y - mb) ** 2 for y in rb) ** 0.5
    return round(cov / (va * vb), 4) if va and vb else 0.0


def main() -> None:
    out: dict = {"tag": TAG,
                 "note": "길이 기준선 = score(-len(code)) 의 AUC. AUC 의 자명 기준선을 "
                         "0.5 대신 이 값으로 읽는다.",
                 "splits": {}}
    for split, label in SPLITS:
        sp = ROOT / "out" / f"{TAG}_logprob_{split}.jsonl"
        dp = ROOT / "data" / f"{split}.jsonl"
        if not (sp.exists() and dp.exists()):
            out["splits"][split] = {"status": "미실행"}
            continue
        sc = [json.loads(l) for l in sp.open()]
        da = [json.loads(l) for l in dp.open()]
        L, S, Y, lenrecs = [], [], [], []
        for s, d in zip(sc, da):
            m = CODE.search(d["prompt"])
            c = m.group(1) if m else d["prompt"]
            L.append(len(c)); S.append(s["score"])
            Y.append(1 if s["meta"]["label"] == "vuln" else 0)
            lenrecs.append({"meta": s["meta"], "score": -len(c)})
        e = {
            "label": label, "n": len(sc),
            "auc_model": auc(sc),
            "auc_length_only": auc(lenrecs),
            "margin_over_length": round(auc(sc) - auc(lenrecs), 4),
            "rho_score_length": spearman(S, L),
            "rho_gold_length": spearman(Y, L),
            "median_len_vuln": st.median([l for l, y in zip(L, Y) if y]),
            "median_len_safe": st.median([l for l, y in zip(L, Y) if not y]),
        }
        out["splits"][split] = e
        print(f"[{label:20s}] 모델 {e['auc_model']:.4f}  길이만 {e['auc_length_only']:.4f}  "
              f"차이 {e['margin_over_length']:+.4f}   "
              f"ρ(score,len) {e['rho_score_length']:+.4f} / ρ(gold,len) {e['rho_gold_length']:+.4f}")

    p = ROOT / "out" / f"length_baseline_{TAG}.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"→ {p}")


if __name__ == "__main__":
    main()
