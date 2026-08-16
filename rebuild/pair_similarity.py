"""
쌍 단서 분석 4단계 — **두 판본의 유사도**가 지배 변수다 (§7-5 1순위, 비용 $0)
================================================================================
1~3단계(`pair_cue_analysis` / `pair_cue_joint` / `pair_cue_lang`)는
diff 크기·어휘 변화·언어·코드 길이를 통제해도 코퍼스 격차가 남는다고 했다.
여기서 그 격차의 정체를 찾는다.

**재는 것: 쌍 안에서 취약본과 패치본이 얼마나 비슷한가** (`difflib.SequenceMatcher` 비율).

이게 중요한 이유:
  "패치 전후"는 보통 **거의 같은 코드**다(작은 수정 하나). 유사도가 0.95 를 넘는다.
  반면 서로 **다른 코드 두 개**를 놓고 "어느 쪽이 취약한가"를 묻는 것은 훨씬 쉬운 과제다.
  두 과제를 같은 표에 놓으면 안 된다.

**이 스크립트가 밝힌 것 (요약):**
  내부 test 를 `cve_id` 로 묶어 만든 "쌍"은 **유사도 중앙값 0.394** 다 —
  같은 함수의 패치 전후가 아니라 **같은 CVE 에 속한 서로 다른 코드 조각** 두 개다.
  CleanVul(0.923)·PrimeVul(0.979)만 진짜 패치 쌍이다.

**주의 (거의 항등에 가까운 부분).** 두 입력이 거의 같으면 두 출력도 거의 같다.
유사도가 높을수록 점수차가 작아지는 것 자체는 놀랍지 않다.
**놀라운 것은 그 방향이 우연 아래(0.477)로 내려가고 동점이 29.6% 라는 것** —
모델이 "작지만 결정적인 차이"를 잡는 장치를 갖고 있지 않다는 뜻이다.

출력: out/pair_similarity_{tag}.json
실행: python3 rebuild/pair_similarity.py [tag]
"""
from __future__ import annotations

import difflib
import json
import re
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TAG = sys.argv[1] if len(sys.argv) > 1 else "v1"
CODE = re.compile(r"```[^\n]*\n(.*?)\n```", re.S)
SP = [("test", "내부test (CVE 묶음)"), ("cleanvul_v2_report", "CleanVul"),
      ("primevul_report", "PrimeVul")]
BINS = [(0.0, 0.30), (0.30, 0.60), (0.60, 0.85), (0.85, 0.95), (0.95, 1.01)]


def pair_key(m: dict) -> str | None:
    return m.get("pair_id") or m.get("cve_id") or None


def code_of(p: str) -> str:
    m = CODE.search(p)
    return m.group(1) if m else p


def build(split: str) -> list[dict]:
    sc = [json.loads(l) for l in (ROOT / "out" / f"{TAG}_logprob_{split}.jsonl").open()]
    da = [json.loads(l) for l in (ROOT / "data" / f"{split}.jsonl").open()]
    g = defaultdict(lambda: defaultdict(list))
    for s, d in zip(sc, da):
        k = pair_key(s["meta"])
        if k:
            g[k][s["meta"]["label"]].append((s["score"], code_of(d["prompt"])))
    rows = []
    for v in g.values():
        if len(v.get("vuln", [])) != 1 or len(v.get("safe", [])) != 1:
            continue
        (sv, cv), (ss, cs) = v["vuln"][0], v["safe"][0]
        rows.append({"sim": difflib.SequenceMatcher(None, cv, cs).ratio(),
                     "ok": sv > ss, "tie": sv == ss})
    return rows


def acc(rs: list[dict]) -> tuple[float | None, int]:
    return (round(sum(r["ok"] for r in rs) / len(rs), 4), len(rs)) if rs else (None, 0)


def main() -> None:
    R = {n: build(s) for s, n in SP}
    out: dict = {"tag": TAG,
                 "note": "유사도 = difflib.SequenceMatcher(취약본, 패치본).ratio()",
                 "WARNING": "예측 대조다. 두 입력이 비슷하면 두 출력도 비슷해지는 부분이 "
                            "항등에 가깝다는 점을 감안해 읽는다.",
                 "per_split": {}, "by_similarity_bin": {}, "pooled_by_bin": {}}

    print("=== 쌍 내 유사도 분포 ===")
    for _, n in SP:
        rows = R[n]
        sims = [r["sim"] for r in rows]
        okm = st.median([r["sim"] for r in rows if r["ok"]])
        ngm = st.median([r["sim"] for r in rows if not r["ok"]])
        e = {"n_pairs": len(rows), "sim_median": round(st.median(sims), 4),
             "ratio_sim_lt_0.3": round(sum(x < 0.3 for x in sims) / len(sims), 4),
             "ratio_sim_ge_0.8": round(sum(x >= 0.8 for x in sims) / len(sims), 4),
             "sim_median_correct": round(okm, 4), "sim_median_wrong": round(ngm, 4),
             "rank_acc": acc(rows)[0]}
        out["per_split"][n] = e
        print(f"  {n:>18}: 쌍 {len(rows):5d}  유사도 중앙값 {e['sim_median']}  "
              f"<0.3 {e['ratio_sim_lt_0.3']:.1%}  ≥0.8 {e['ratio_sim_ge_0.8']:.1%}")
        print(f"  {'':>18}  정답쌍 유사도 {e['sim_median_correct']} / 오답쌍 {e['sim_median_wrong']}")

    print("\n=== 유사도 구간별 쌍 내 순위 정확도 ===")
    header = f"{'유사도':>12} | " + " | ".join(f"{n:>15}" for _, n in SP) + " |         pooled"
    print(header)
    for lo, hi in BINS:
        key = f"{lo:.2f}-{hi:.2f}"
        out["by_similarity_bin"][key] = {}
        row, pool = [], []
        for _, n in SP:
            sub = [r for r in R[n] if lo <= r["sim"] < hi]
            pool += sub
            a, k = acc(sub)
            out["by_similarity_bin"][key][n] = {"rank_acc": a, "n": k}
            row.append(f"{a} (n={k})")
        ap, kp = acc(pool)
        out["pooled_by_bin"][key] = {
            "rank_acc": ap, "n": kp,
            "tie_rate": round(sum(r["tie"] for r in pool) / len(pool), 4) if pool else None}
        print(f"{key:>12} | " + " | ".join(f"{x:>15}" for x in row)
              + f" | {ap} (n={kp}) 동점 {out['pooled_by_bin'][key]['tie_rate']}")

    p = ROOT / "out" / f"pair_similarity_{TAG}.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"→ {p}")


if __name__ == "__main__":
    main()
