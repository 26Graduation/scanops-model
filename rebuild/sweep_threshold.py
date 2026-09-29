"""
ScanOps v3 — logprob 임계값 스윕 (tune에서 고르고 report에서 보고)
==================================================================
score_logprob.py 산출물을 읽어 임계값 τ를 스윕한다.
  - τ는 tune split에서 F1 최대점으로 고른다 (사양서 §3.4)
  - 최종 숫자는 report split에서 보고. 두 숫자를 모두 남긴다(격차=과적합 신호).
  - 채점은 bench_common.score / pairwise_score 그대로 사용.

실행: python rebuild/sweep_threshold.py <tag> <base>   # base 예: primevul, cleanvul_v2 → v1, 내부는 internal
출력: out/{tag}_sweep_{base}.json  (전체 곡선 + 선택 τ + tune/report 지표)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from bench_common import pairwise_score, score

ROOT = Path(__file__).resolve().parent


def load(tag: str, split: str) -> list[dict]:
    p = ROOT / "out" / f"{tag}_logprob_{split}.jsonl"
    return [json.loads(l) for l in p.open()] if p.exists() else []


def apply_tau(recs: list[dict], tau: float) -> list[dict]:
    return [{"meta": r["meta"], "label": "vuln" if r["score"] >= tau else "safe"} for r in recs]


def auc(recs: list[dict]) -> float:
    """AUROC — 임계값과 무관한 '진짜 판별력'. 50:50 균형셋에서 F1은 전량양성으로 부풀지만
    AUC는 부풀지 않는다. 자명 기준선과 함께 반드시 병기한다."""
    import bisect
    v = sorted(r["score"] for r in recs if r["meta"]["label"] == "vuln")
    s = sorted(r["score"] for r in recs if r["meta"]["label"] == "safe")
    if not v or not s:
        return 0.0
    n = 0.0
    for a in v:
        lo, hi = bisect.bisect_left(s, a), bisect.bisect_right(s, a)
        n += lo + 0.5 * (hi - lo)
    return round(n / (len(v) * len(s)), 4)


def trivial_baseline(recs: list[dict]) -> dict:
    """'무조건 VULNERABLE' 자명 기준선 — 균형셋에서 F1 0.667이 공짜로 나온다.
    우리 숫자가 이걸 못 넘으면 이긴 게 아니다."""
    return score([{"meta": r["meta"], "label": "vuln"} for r in recs])


def curve(recs: list[dict]) -> list[dict]:
    scores = sorted({round(r["score"], 3) for r in recs})
    # 후보 τ: 점수 분위 + 0 (argmax 기준점)
    step = max(1, len(scores) // 200)
    taus = sorted(set(scores[::step] + [0.0]))
    out = []
    for t in taus:
        s = score(apply_tau(recs, t))
        s["tau"] = t
        out.append(s)
    return out


def main() -> None:
    tag, base = sys.argv[1], sys.argv[2]
    if base == "test":
        # 내부 test는 통째로 report용(§3.4). 운영점은 val에서 고른다.
        tune, report = load(tag, "val_v3") or load(tag, "val"), load(tag, "test")
        if not tune:
            raise SystemExit("내부 test의 τ는 val에서 골라야 한다 — val logprob 파일이 없다")
    else:
        tune, report = load(tag, f"{base}_tune"), load(tag, f"{base}_report")
    c = curve(tune)
    best = max(c, key=lambda x: x["f1"])
    # F1 최대 τ가 전량양성으로 붕괴하는 경우가 있어(균형셋의 구조적 함정),
    # "FPR 상한 안에서 F1 최대" τ도 함께 고른다 — 운영에서 실제로 쓸 수 있는 점.
    best_capped = max([x for x in c if x["fpr"] <= 0.35] or c, key=lambda x: x["f1"])
    res = {
        "tag": tag, "base": base, "chosen_tau": best["tau"],
        "auc_tune": auc(tune), "auc_report": auc(report),
        "trivial_all_vuln_report": trivial_baseline(report),
        "tune": best,
        "report": {**score(apply_tau(report, best["tau"])), "tau": best["tau"]},
        "capped_fpr35_tau": best_capped["tau"],
        "capped_fpr35_tune": best_capped,
        "capped_fpr35_report": {**score(apply_tau(report, best_capped["tau"])),
                                "tau": best_capped["tau"]},
        "argmax_baseline_report": score(apply_tau(report, 0.0)),
        "curve_tune": c,
    }
    if report and "pair_id" in report[0]["meta"]:
        res["report_pairwise"] = pairwise_score(apply_tau(report, best["tau"]))
        res["tune_pairwise"] = pairwise_score(apply_tau(tune, best["tau"]))
        # pair_correct 최대화 τ도 따로 (STRETCH 목표용)
        pc = max(({"tau": t["tau"], **pairwise_score(apply_tau(tune, t["tau"]))} for t in c),
                 key=lambda x: x["pair_correct"]["rate"])
        res["best_pair_tau"] = pc["tau"]
        res["report_pairwise_at_best_pair_tau"] = pairwise_score(apply_tau(report, pc["tau"]))
    out = ROOT / "out" / f"{tag}_sweep_{base}.json"
    out.write_text(json.dumps(res, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in res.items() if k != "curve_tune"}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
