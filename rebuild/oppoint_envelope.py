"""
OPPOINT-ENVELOPE — 참고 계산 (판정에 쓰지 않는다)
==================================================
`oppoint_op.py` 가 `OP-INSUFFICIENT` 를 냈다. 그 뜻을 정확히 적기 위한 **사후 참고** 계산이다.
**여기서 나온 어떤 수치도 τ 선정이나 게이트 판정에 쓰지 않는다** (사양 §8-4·§8-6).

계산 세 가지:

**(1) AUC 가 주는 precision 상한 곡선.**
  ROC 가 오목(concave)하면 Youden J = TPR − FPR ≤ 2·AUC − 1 이다
  (오목 ROC 는 (0,0)-(f,t) 와 (f,t)-(1,1) 두 현 위에 있으므로 AUC ≥ (1+t−f)/2).
  유병률 50:50 균형셋에서 precision = TPR/(TPR+FPR) 이므로, recall t 에서
      FPR ≥ max(0, t − J_max)  →  precision ≤ t / (t + max(0, t − J_max)).
  **이건 상한(포락선)이지 달성 가능성이 아니다.** 낮은 recall 에서는 상한이 1.0 까지 열린다.
  따라서 "AUC 가 precision 0.70 을 금지한다"고 쓰면 틀린다. 실측 곡선을 함께 봐야 한다.

**(2) 실측 곡선에서의 도달 가능성.**
  report split 의 실제 (recall, precision) 곡선에서
    - precision ≥ 0.70 을 만족하는 점 중 최대 recall
    - recall ≥ 0.75 AND FPR ≤ 0.15 를 만족하는 점의 존재 여부
  를 그대로 센다. 이것이 "운영점으로 못 지킨다"의 실증적 내용이다.

**(3) greedy(현 배포) ↔ logprob argmax 일치율.**
  OP-0(τ=0)을 "현 배포와 같은 지점"이라 부르려면 둘이 실제로 같은 판정을 내는지 확인해야 한다.

실행: python3 rebuild/oppoint_envelope.py [tag]
출력: out/oppoint_envelope_{tag}.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from bench_common import score              # noqa: E402
from sweep_threshold import apply_tau, auc   # noqa: E402

TAG = sys.argv[1] if len(sys.argv) > 1 else "v1"
PREC_TARGET = 0.70
RECALL_FLOOR = 0.10
GATE_R, GATE_F = 0.75, 0.15

SPLITS = [
    ("test", "내부 test"),
    ("cleanvul_v2_report", "CleanVul_v2 report"),
    ("primevul_report", "PrimeVul report"),
    ("cvefixes157", "CVEfixes 157"),
    ("cybernative154", "CyberNative 154"),
]


def load(split: str) -> list[dict]:
    p = ROOT / "out" / f"{TAG}_logprob_{split}.jsonl"
    return [json.loads(l) for l in p.open()] if p.exists() else []


def envelope(a: float, recalls=(0.90, 0.75, 0.50, 0.30, 0.20, 0.10)) -> list[dict]:
    """오목 ROC 가정에서 AUC=a 가 허용하는 precision 상한 (균형셋)."""
    j = 2 * a - 1
    out = []
    for t in recalls:
        f_min = max(0.0, t - j)
        p_max = t / (t + f_min) if (t + f_min) else 1.0
        out.append({"recall": t, "fpr_min": round(f_min, 4), "precision_max": round(p_max, 4)})
    return out


def full_curve(recs: list[dict]) -> list[dict]:
    xs = sorted({round(r["score"], 4) for r in recs})
    step = max(1, len(xs) // 600)
    taus = sorted(set(xs[::step] + [xs[0] - 1.0, 0.0, xs[-1] + 1.0]))
    out = []
    for t in taus:
        s = score(apply_tau(recs, t))
        s["tau"] = t
        out.append(s)
    return out


def agreement(recs: list[dict]) -> dict | None:
    """τ=0 판정과 저장된 argmax_label 의 일치율 — OP-0 ≡ greedy 확인."""
    if "argmax_label" not in recs[0]:
        return None
    tau0 = apply_tau(recs, 0.0)
    same = sum(1 for a, r in zip(tau0, recs) if a["label"] == r["argmax_label"])
    return {"n": len(recs), "agree": same, "rate": round(same / len(recs), 4)}


def main() -> None:
    out: dict = {
        "WARNING": "사후 참고 계산이다. τ 선정·게이트 판정에 쓰지 않는다 (사양 §8-4·§8-6).",
        "tag": TAG, "precision_target": PREC_TARGET, "recall_floor": RECALL_FLOOR,
        "splits": {},
    }
    for split, label in SPLITS:
        recs = load(split)
        if not recs:
            out["splits"][split] = {"label": label, "status": "미실행 — logprob 파일 없음"}
            continue
        a = auc(recs)
        cur = full_curve(recs)

        hit_prec = [c for c in cur if c["precision"] >= PREC_TARGET and c["recall"] >= RECALL_FLOOR]
        hit_gate = [c for c in cur if c["recall"] >= GATE_R and c["fpr"] <= GATE_F]
        best_prec_at_r = {}
        for r_floor in (0.75, 0.50, 0.30, 0.10):
            cand = [c for c in cur if c["recall"] >= r_floor]
            best_prec_at_r[str(r_floor)] = max((c["precision"] for c in cand), default=None)

        out["splits"][split] = {
            "label": label, "n": len(recs), "auc": a,
            "youden_j_max_from_auc": round(2 * a - 1, 4),
            "auc_precision_envelope": envelope(a),
            "measured_max_precision_at_recall_at_least": best_prec_at_r,
            f"measured_taus_with_precision>={PREC_TARGET}_and_recall>={RECALL_FLOOR}": len(hit_prec),
            "measured_best_recall_among_them": max((c["recall"] for c in hit_prec), default=None),
            f"measured_taus_with_recall>={GATE_R}_and_fpr<={GATE_F}": len(hit_gate),
            "greedy_vs_logprob_argmax": agreement(recs),
        }
        print(f"[{label}] n={len(recs)} auc={a} J_max={round(2*a-1,4)}  "
              f"prec>=.70&rec>=.10 점 {len(hit_prec)}개  "
              f"rec>=.75&fpr<=.15 점 {len(hit_gate)}개  "
              f"maxP@rec>=.75 {best_prec_at_r['0.75']}  "
              f"argmax일치 {out['splits'][split]['greedy_vs_logprob_argmax']}")

    p = ROOT / "out" / f"oppoint_envelope_{TAG}.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"→ {p}")


if __name__ == "__main__":
    main()
