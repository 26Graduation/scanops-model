"""
쌍 판별 실패의 원인 규명 — 1단계 (§7-5 1순위, 비용 $0)
=========================================================
`pair_discrimination_v1.json` 이 남긴 질문:
  같은 형식(같은 커밋의 취약본·패치본)이고 둘 다 학습에 들어 있는 두 코퍼스가
  왜 **CVEfixes 0.9068 vs PrimeVul 0.4931** 로 갈리는가.

`OPPOINT_RESULTS.md` §1-4 가 적은 세 가설 중 **첫 두 개**를 여기서 검정한다.
학습을 돌리지 않고, 기존 데이터와 점수만 쓴다.

  H1 "표면 단서"  — CVEfixes 쌍은 패치가 **크고 눈에 띈다**. 모델이 그 형태를 학습했고,
                    단서가 없는 PrimeVul 에서 무너진다.
                    → 예측: 쌍 판별 **정답 쌍의 diff 가 오답 쌍보다 크다.**
                      그리고 CVEfixes 쌍의 diff 가 PrimeVul 쌍보다 크다.
  H2 "난이도"     — PrimeVul 이 그냥 더 어렵다(C/C++ 전용·미묘한 결함).
                    → 예측: diff 크기를 맞춰도(같은 구간에서 비교해도) PrimeVul 이 낮다.

**H1 과 H2 는 배타적이지 않다.** 이 분석은 어느 쪽 **예측이 맞는지**만 본다. 인과가 아니다.

재는 것 (쌍 단위):
  - `diff_lines`      난이도 무관 크기: 두 판본의 라인 단위 차이 개수 (difflib)
  - `char_delta`      |len(safe) − len(vuln)|
  - `added_guard`     패치본에만 등장하는 방어 키워드가 있는가 (경계검사·검증·이스케이프 계열)
  - `correct`         score[vuln] > score[safe] 인가
  - `tie`             두 점수가 완전히 같은가

실행: python3 rebuild/pair_cue_analysis.py [tag]
출력: out/pair_cue_{tag}.json
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
sys.path.insert(0, str(ROOT))

TAG = sys.argv[1] if len(sys.argv) > 1 else "v1"
SPLITS = [("test", "내부 test (CVEfixes 홀드아웃)"),
          ("cleanvul_v2_report", "CleanVul_v2 report"),
          ("primevul_report", "PrimeVul report")]

# 패치본에만 나타나면 "눈에 띄는 방어"로 보는 토큰. 언어 중립적인 것만 골랐다.
GUARD = re.compile(
    r"\b(if|assert|check|valid|verify|sanitiz|escape|encode|quote|bound|limit|clamp|"
    r"strn?cpy_s|snprintf|strlcpy|len|size|length|count|null|NULL|nullptr|None|"
    r"overflow|range|index|offset)\b", re.I)

CODE_FENCE = re.compile(r"```[^\n]*\n(.*?)\n```", re.S)


def pair_key(meta: dict) -> str | None:
    return meta.get("pair_id") or meta.get("cve_id") or None


def code_of(prompt: str) -> str:
    m = CODE_FENCE.search(prompt)
    return m.group(1) if m else prompt


def guard_tokens(code: str) -> set[str]:
    return {m.group(0).lower() for m in GUARD.finditer(code)}


def summarize(rows: list[dict], key: str) -> dict | None:
    xs = [r[key] for r in rows if r.get(key) is not None]
    if not xs:
        return None
    return {"n": len(xs), "mean": round(st.mean(xs), 2),
            "median": round(st.median(xs), 2)}


def main() -> None:
    out: dict = {"tag": TAG,
                 "WARNING": "예측 대조일 뿐 인과가 아니다. H1·H2 는 배타적이지 않다.",
                 "splits": {}}

    for split, label in SPLITS:
        sp = ROOT / "out" / f"{TAG}_logprob_{split}.jsonl"
        dp = ROOT / "data" / f"{split}.jsonl"
        if not (sp.exists() and dp.exists()):
            out["splits"][split] = {"status": "미실행"}
            continue
        scores = [json.loads(l) for l in sp.open()]
        data = [json.loads(l) for l in dp.open()]
        assert len(scores) == len(data), f"{split}: 점수/데이터 길이 불일치"

        g = defaultdict(lambda: defaultdict(list))
        for s, d in zip(scores, data):
            k = pair_key(s["meta"])
            if k is None:
                continue
            g[k][s["meta"]["label"]].append((s["score"], code_of(d["prompt"])))

        rows = []
        for k, v in g.items():
            if len(v.get("vuln", [])) != 1 or len(v.get("safe", [])) != 1:
                continue
            (sv, cv), (ss, cs) = v["vuln"][0], v["safe"][0]
            dl = sum(1 for line in difflib.unified_diff(
                cv.splitlines(), cs.splitlines(), n=0) if line[:1] in "+-"
                and not line.startswith(("+++", "---")))
            rows.append({
                "pair": k,
                "diff_lines": dl,
                "char_delta": abs(len(cs) - len(cv)),
                "added_guard": bool(guard_tokens(cs) - guard_tokens(cv)),
                "correct": sv > ss,
                "tie": sv == ss,
            })

        ok = [r for r in rows if r["correct"]]
        ng = [r for r in rows if not r["correct"]]
        ties = [r for r in rows if r["tie"]]
        with_guard = [r for r in rows if r["added_guard"]]
        wo_guard = [r for r in rows if not r["added_guard"]]

        e = {
            "label": label, "n_pairs": len(rows),
            "rank_acc": round(len(ok) / len(rows), 4) if rows else None,
            "tie_rate": round(len(ties) / len(rows), 4) if rows else None,
            "diff_lines_all": summarize(rows, "diff_lines"),
            "diff_lines_correct": summarize(ok, "diff_lines"),
            "diff_lines_wrong": summarize(ng, "diff_lines"),
            "char_delta_all": summarize(rows, "char_delta"),
            "guard_added_ratio": round(len(with_guard) / len(rows), 4) if rows else None,
            "rank_acc_when_guard_added": round(
                sum(r["correct"] for r in with_guard) / len(with_guard), 4) if with_guard else None,
            "rank_acc_when_no_guard": round(
                sum(r["correct"] for r in wo_guard) / len(wo_guard), 4) if wo_guard else None,
        }
        # diff 크기 구간별 순위 정확도 (H2 검정용 — 크기를 맞춰도 갈리는가)
        bins = [(0, 5), (6, 20), (21, 60), (61, 10**9)]
        e["rank_acc_by_diff_bin"] = {}
        for lo, hi in bins:
            b = [r for r in rows if lo <= r["diff_lines"] <= hi]
            e["rank_acc_by_diff_bin"][f"{lo}-{hi if hi < 10**9 else '∞'}"] = {
                "n": len(b),
                "rank_acc": round(sum(r["correct"] for r in b) / len(b), 4) if b else None}
        out["splits"][split] = e

        print(f"[{label}] 쌍 {len(rows)}  순위 {e['rank_acc']}  동점 {e['tie_rate']}")
        print(f"    diff 라인 전체 {e['diff_lines_all']}")
        print(f"      정답쌍 {e['diff_lines_correct']}  오답쌍 {e['diff_lines_wrong']}")
        print(f"    방어토큰 추가 비율 {e['guard_added_ratio']}  "
              f"(추가 시 순위 {e['rank_acc_when_guard_added']} / 미추가 시 {e['rank_acc_when_no_guard']})")
        for k2, v2 in e["rank_acc_by_diff_bin"].items():
            print(f"    diff {k2:>8} 라인: n={v2['n']:5d} 순위 {v2['rank_acc']}")

    p = ROOT / "out" / f"pair_cue_{TAG}.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"→ {p}")


if __name__ == "__main__":
    main()
