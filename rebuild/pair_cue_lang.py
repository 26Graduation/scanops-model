"""
쌍 단서 분석 3단계 — **언어와 코드 길이를 통제**한다 (§7-5 1순위, 비용 $0)
==========================================================================
`pair_cue_joint.py` 가 남긴 질문: diff 크기·어휘 변화를 통제해도
내부 test > CleanVul > PrimeVul 순서가 남는다. 다음 후보 두 개를 지운다.

  C1 **언어** — PrimeVul 은 **전량 C/C++** 이다. 내부 test 는 C/C++ 가 297/1,197 뿐이다.
      §3-4 언어별 표에서 C/C++ 가 어느 벤치에서든 최저였다.
      → C/C++ 쌍만 놓고 비교하면 격차가 줄어드는가?
  C2 **코드 길이** — 긴 코드일수록 어렵다면, 길이 분포 차이가 격차를 만들 수 있다.
      → 길이 구간을 맞춰도 격차가 남는가?

**둘 다 "격차를 만드는 요인인가"를 보는 것이지 인과 규명이 아니다.**

출력: out/pair_cue_lang_{tag}.json
실행: python3 rebuild/pair_cue_lang.py [tag]
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
SP = [("test", "내부test"), ("cleanvul_v2_report", "CleanVul"), ("primevul_report", "PrimeVul")]

# 벤치마다 lang_group 표기가 다르다 — C/C++ 계열로 정규화
CPP = {"C/C++", "C", "C++"}


def pair_key(m: dict) -> str | None:
    return m.get("pair_id") or m.get("cve_id") or None


def code_of(p: str) -> str:
    m = CODE.search(p)
    return m.group(1) if m else p


def build(split: str) -> list[dict]:
    sp = ROOT / "out" / f"{TAG}_logprob_{split}.jsonl"
    dp = ROOT / "data" / f"{split}.jsonl"
    sc = [json.loads(l) for l in sp.open()]
    da = [json.loads(l) for l in dp.open()]
    g = defaultdict(lambda: defaultdict(list))
    for s, d in zip(sc, da):
        k = pair_key(s["meta"])
        if k:
            g[k][s["meta"]["label"]].append(
                (s["score"], code_of(d["prompt"]), s["meta"].get("lang_group")))
    rows = []
    for k, v in g.items():
        if len(v.get("vuln", [])) != 1 or len(v.get("safe", [])) != 1:
            continue
        (sv, cv, lg), (ss, cs, _) = v["vuln"][0], v["safe"][0]
        dl = sum(1 for line in difflib.unified_diff(cv.splitlines(), cs.splitlines(), n=0)
                 if line[:1] in "+-" and not line.startswith(("+++", "---")))
        rows.append({"lang": lg, "is_cpp": lg in CPP, "dl": dl,
                     "nchar": len(cv), "ok": sv > ss, "tie": sv == ss})
    return rows


def acc(rs: list[dict]) -> tuple[float | None, int]:
    return (round(sum(r["ok"] for r in rs) / len(rs), 4), len(rs)) if rs else (None, 0)


def main() -> None:
    R = {n: build(s) for s, n in SP}
    out: dict = {"tag": TAG,
                 "WARNING": "격차 요인 대조일 뿐 인과가 아니다.",
                 "C1_language": {}, "C2_length": {}, "C1xC2": {}}

    print("=== C1: C/C++ 쌍만 놓고 비교 ===")
    for _, n in SP:
        cpp = [r for r in R[n] if r["is_cpp"]]
        a_all, k_all = acc(R[n])
        a_cpp, k_cpp = acc(cpp)
        dl = st.median([r["dl"] for r in cpp]) if cpp else None
        out["C1_language"][n] = {"all": {"rank_acc": a_all, "n": k_all},
                                 "cpp_only": {"rank_acc": a_cpp, "n": k_cpp,
                                              "diff_lines_median": dl}}
        print(f"  {n:>10}: 전체 {a_all} (n={k_all})   C/C++ 만 {a_cpp} (n={k_cpp}, diff중앙값 {dl})")

    print("\n=== C2: 코드 길이(취약본 문자 수) 구간별 ===")
    bins = [(0, 500), (501, 1500), (1501, 4000), (4001, 10**9)]
    for lo, hi in bins:
        row = []
        for _, n in SP:
            a, k = acc([r for r in R[n] if lo <= r["nchar"] <= hi])
            row.append(f"{a} (n={k})")
            out["C2_length"].setdefault(f"{lo}-{hi if hi < 10**9 else 'inf'}", {})[n] = \
                {"rank_acc": a, "n": k}
        print(f"  {lo:>5}-{hi if hi < 10**9 else '∞':>5} 자: " + " | ".join(f"{x:>16}" for x in row))

    print("\n=== C1×C2: C/C++ 만, 길이 구간별 ===")
    for lo, hi in bins:
        row = []
        for _, n in SP:
            a, k = acc([r for r in R[n] if r["is_cpp"] and lo <= r["nchar"] <= hi])
            row.append(f"{a} (n={k})")
            out["C1xC2"].setdefault(f"{lo}-{hi if hi < 10**9 else 'inf'}", {})[n] = \
                {"rank_acc": a, "n": k}
        print(f"  {lo:>5}-{hi if hi < 10**9 else '∞':>5} 자: " + " | ".join(f"{x:>16}" for x in row))

    p = ROOT / "out" / f"pair_cue_lang_{TAG}.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"→ {p}")


if __name__ == "__main__":
    main()
