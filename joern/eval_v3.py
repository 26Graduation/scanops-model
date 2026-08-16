"""Phase 3 — v3 파이프라인 벤치 (사전등록: REPORT_V3 §3-0).

  python joern/eval_v3.py sample     # 층화 240건
  python joern/eval_v3.py report     # 전건 (V3-SUCCESS 시에만)

arm:
  b) LLM only              — 어젯밤과 동일 (llm_score / detected 대용)
  a) LLM + 자체graph        — 어젯밤 채택 arm (기준선)
  j) Joern v3 단독
  c) Joern v3 + Critic      — CRITIC 판정에 따라 적용 방식이 달라진다
자명 기준선(all-vuln / all-safe)을 항상 병기한다.
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "rebuild" / "out"

SEED = 42
BOOT = 2000


def boot_ci(hits: int, n: int, iters: int = BOOT) -> list[float]:
    if n == 0:
        return [0.0, 0.0]
    rng = random.Random(SEED)
    obs = [1] * hits + [0] * (n - hits)
    vals = []
    for _ in range(iters):
        s = sum(rng.choice(obs) for _ in range(n))
        vals.append(s / n)
    vals.sort()
    return [round(vals[int(0.025 * iters)], 4), round(vals[int(0.975 * iters) - 1], 4)]


def metrics(pred: list[str], gold: list[str]) -> dict:
    """pred/gold ∈ {vuln, safe}"""
    tp = sum(1 for p, g in zip(pred, gold) if p == "vuln" and g == "vuln")
    fp = sum(1 for p, g in zip(pred, gold) if p == "vuln" and g == "safe")
    fn = sum(1 for p, g in zip(pred, gold) if p == "safe" and g == "vuln")
    tn = sum(1 for p, g in zip(pred, gold) if p == "safe" and g == "safe")
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"n": len(pred), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "fpr": round(fpr, 4), "f1": round(f1, 4),
            "precision_ci95": boot_ci(tp, tp + fp)}


def main() -> int:
    split = sys.argv[1] if len(sys.argv) > 1 else "sample"
    rows = [json.loads(l) for l in (OUT / f"joern_v3_raw_cleanvul_v2_{split}.jsonl").open()]

    # Critic 결과 (tune 게이트 실행분 + report 적용분)
    critic: dict[str, str] = {}
    for name in (f"critic_raw_cleanvul_v2_{split}.jsonl", "critic_raw_cleanvul_v2_tune.jsonl"):
        p = OUT / name
        if p.exists():
            for line in p.open():
                try:
                    o = json.loads(line)
                    critic.setdefault(o["case_id"], o["critic"])
                except Exception:  # noqa: BLE001
                    pass

    gate = {}
    gp = OUT / "critic_gate_tune.json"
    if gp.exists():
        gate = json.loads(gp.read_text())
    cverdict = gate.get("verdict", "CRITIC-KILL")

    gold = [r["label"] for r in rows]
    tau = 0.4375  # 어젯밤 사전등록값

    def llm_pred(r: dict) -> str:
        s = r.get("llm_score")
        return "vuln" if (s is not None and s >= tau) else "safe"

    arms: dict[str, list[str]] = {
        "all-vuln (자명)": ["vuln"] * len(rows),
        "all-safe (자명)": ["safe"] * len(rows),
        "b) LLM only": [llm_pred(r) for r in rows],
        "a) LLM + 자체graph": [
            "vuln" if (llm_pred(r) == "vuln" or r.get("graph_verdict") == "vuln") else "safe"
            for r in rows],
        "j) Joern v3 단독": [
            "vuln" if r["joern_verdict"] == "vuln" else "safe" for r in rows],
    }

    # Critic arm — 판정별로 적용 방식이 다르다(사전등록 §3-0 / Phase 4)
    def critic_arm(r: dict) -> str:
        if r["joern_verdict"] != "vuln":
            return "vuln" if (llm_pred(r) == "vuln" or r.get("graph_verdict") == "vuln") else "safe"
        cv = critic.get(r["case_id"])
        if cverdict == "CRITIC-GO" and cv == "YES":
            return "safe"          # Critic 이 sanitized 라 하면 덮는다
        return "vuln"              # WEAK/KILL/UNPARSED/NO → vuln 유지
    arms["c) Joern v3 + Critic"] = [critic_arm(r) for r in rows]

    # Joern v3 단독 precision (게이트 지표)
    jv = [r for r in rows if r["joern_verdict"] == "vuln"]
    jhits = sum(1 for r in jv if r["label"] == "vuln")

    res = {
        "split": split, "n": len(rows),
        "critic_gate_verdict": cverdict,
        "joern_v3_vuln": len(jv),
        "joern_v3_precision": round(jhits / max(1, len(jv)), 4),
        "joern_v3_precision_ci95": boot_ci(jhits, len(jv)),
        "verdict_dist": {v: sum(1 for r in rows if r["joern_verdict"] == v)
                         for v in sorted({r["joern_verdict"] for r in rows})},
        "arms": {k: metrics(v, gold) for k, v in arms.items()},
        "by_lang": {},
    }
    for lang in sorted({r["lang"] for r in rows}):
        idx = [i for i, r in enumerate(rows) if r["lang"] == lang]
        res["by_lang"][lang] = {
            k: metrics([v[i] for i in idx], [gold[i] for i in idx])
            for k, v in arms.items() if k.startswith(("j)", "c)", "a)"))
        }

    (OUT / f"joern_v3_eval_{split}.json").write_text(
        json.dumps(res, indent=2, ensure_ascii=False))

    print(f"=== v3 eval {split} n={len(rows)} (critic gate={cverdict}) ===")
    print(f"joern_v3 vuln={len(jv)} precision={res['joern_v3_precision']} "
          f"CI={res['joern_v3_precision_ci95']}")
    print(f"verdict 분포: {res['verdict_dist']}")
    print(f"\n{'arm':24s} {'prec':>7s} {'CI':>18s} {'recall':>7s} {'FPR':>7s} {'F1':>7s}")
    for k, m in res["arms"].items():
        print(f"{k:24s} {m['precision']:7.4f} {str(m['precision_ci95']):>18s} "
              f"{m['recall']:7.4f} {m['fpr']:7.4f} {m['f1']:7.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
