"""Phase 3 검증 — 정책별 recall/FPR/F1/AUC 를 자명 기준선·자체 graph arm 과 나란히.

입력: rebuild/out/joern_raw_cleanvul_v2_{split}.jsonl (llm_score·graph_verdict 포함)
      rebuild/out/joern_tune_selection.json          (DELTA·TAU — 사전 등록값)
출력: rebuild/out/joern_policy_eval_{split}.json  +  표준출력 마크다운 표

사용: python joern/eval_policies.py sample
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from joern.analyze_joern import auc, prf  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "rebuild" / "out"


def _counts(pred: list[int], y: list[int]) -> dict:
    tp = sum(1 for p, t in zip(pred, y) if p and t)
    fp = sum(1 for p, t in zip(pred, y) if p and not t)
    fn = sum(1 for p, t in zip(pred, y) if not p and t)
    tn = sum(1 for p, t in zip(pred, y) if not p and not t)
    rec = tp / (tp + fn) if tp + fn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "recall": round(rec, 4),
            "precision": round(prec, 4), "fpr": round(fpr, 4), "f1": round(f1, 4)}


def main() -> int:
    split = sys.argv[1] if len(sys.argv) > 1 else "sample"
    rows = [json.loads(l) for l in (OUT / f"joern_raw_cleanvul_v2_{split}.jsonl").open()]
    rows = [r for r in rows if r.get("llm_score") is not None]
    y = [1 if r["label"] == "vuln" else 0 for r in rows]
    s = [float(r["llm_score"]) for r in rows]
    jv = [1 if r["joern_verdict"] == "vuln" else 0 for r in rows]
    gv = [1 if r.get("graph_verdict") == "vuln" else 0 for r in rows]

    sel = json.loads((OUT / "joern_tune_selection.json").read_text())
    DELTA = float(sel["DELTA"])
    TAU = float((sel.get("TAU_fpr35") or sel["TAU_f1max"])["tau"])

    llm_pred = [1 if x >= TAU else 0 for x in s]
    arms: dict[str, dict] = {}

    # 자명 기준선
    arms["all-vuln (자명)"] = _counts([1] * len(y), y)
    arms["all-safe (자명)"] = _counts([0] * len(y), y)
    # LLM 단독 (τ는 tune 사전등록값)
    arms["b) LLM only"] = {**_counts(llm_pred, y), "auc": round(auc(s, y), 4)}
    # LLM + 자체 graph (ablation arm a 재현: graph vuln 을 폴백으로)
    arms["a) LLM + 자체graph"] = _counts([1 if p or g else 0 for p, g in zip(llm_pred, gv)], y)
    # TRUST-JOERN
    arms["TRUST-JOERN"] = _counts(
        [1 if j or p or g else 0 for j, p, g in zip(jv, llm_pred, gv)], y)
    # JOERN-AS-SIGNAL (연속 점수 + δ)
    s_sig = [a + DELTA * b for a, b in zip(s, jv)]
    arms["JOERN-AS-SIGNAL"] = {
        **_counts([1 if (x >= TAU or g) else 0 for x, g in zip(s_sig, gv)], y),
        "auc": round(auc(s_sig, y), 4)}
    # JOERN-NO-BETTER (= arm a)
    arms["JOERN-NO-BETTER"] = arms["a) LLM + 자체graph"]

    res = {"split": split, "n": len(rows), "DELTA": DELTA, "TAU": TAU, "arms": arms}
    (OUT / f"joern_policy_eval_{split}.json").write_text(
        json.dumps(res, ensure_ascii=False, indent=1))

    print(f"\n| arm | n={len(rows)} recall | FPR | precision | F1 | AUC |")
    print("|---|---|---|---|---|---|")
    for k, v in arms.items():
        print(f"| {k} | {v['recall']} | {v['fpr']} | {v['precision']} | {v['f1']} | "
              f"{v.get('auc', '—')} |")
    print(f"\nDELTA={DELTA} TAU={TAU} (tune 사전등록값)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
