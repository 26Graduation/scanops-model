"""Phase 2 분석 — ① tune 에서 DELTA·TAU 선정  ② report 에서 precision 게이트 판정

사전 등록 규율: ①을 먼저 돌려 DELTA·TAU 를 확정하고 문서에 적은 뒤, ②를 돌린다.
결과를 보고 ①의 값을 바꾸지 않는다.

사용:
  python joern/analyze_joern.py tune                 → out/joern_tune_selection.json
  python joern/analyze_joern.py gate sample          → out/joern_gate_sample.json
  python joern/analyze_joern.py gate report          → out/joern_gate_report.json
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "rebuild" / "out"

DELTAS = [0.5, 1.0, 2.0]
BOOT = 2000
SEED = 42


def load(split: str) -> list[dict]:
    p = OUT / f"joern_raw_cleanvul_v2_{split}.jsonl"
    return [json.loads(l) for l in p.open()]


# ── 지표 ────────────────────────────────────────────────────────────────────

def auc(scores: list[float], labels: list[int]) -> float:
    """Mann-Whitney U 기반 ROC-AUC (동점은 0.5)."""
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return float("nan")
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    rpos = sum(r for r, y in zip(ranks, labels) if y == 1)
    return (rpos - len(pos) * (len(pos) + 1) / 2.0) / (len(pos) * len(neg))


def prf(scores: list[float], labels: list[int], tau: float) -> dict:
    tp = sum(1 for s, y in zip(scores, labels) if s >= tau and y == 1)
    fp = sum(1 for s, y in zip(scores, labels) if s >= tau and y == 0)
    fn = sum(1 for s, y in zip(scores, labels) if s < tau and y == 1)
    tn = sum(1 for s, y in zip(scores, labels) if s < tau and y == 0)
    rec = tp / (tp + fn) if tp + fn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tau": round(tau, 4), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": round(rec, 4), "precision": round(prec, 4),
            "fpr": round(fpr, 4), "f1": round(f1, 4)}


def boot_ci(hits: int, n: int, boot: int = BOOT, seed: int = SEED) -> list[float]:
    """이항 비율의 부트스트랩 95% CI (2,000회 재표집)."""
    if n == 0:
        return [float("nan"), float("nan")]
    rng = random.Random(seed)
    data = [1] * hits + [0] * (n - hits)
    vals = []
    for _ in range(boot):
        vals.append(sum(rng.choice(data) for _ in range(n)) / n)
    vals.sort()
    return [round(vals[int(0.025 * boot)], 4), round(vals[int(0.975 * boot) - 1], 4)]


# ── ① tune: DELTA·TAU 선정 ─────────────────────────────────────────────────

def run_tune() -> dict:
    rows = [r for r in load("tune") if r.get("llm_score") is not None]
    labels = [1 if r["label"] == "vuln" else 0 for r in rows]
    jv = [1 if r["joern_verdict"] == "vuln" else 0 for r in rows]
    base = [float(r["llm_score"]) for r in rows]

    per_delta = {}
    for d in DELTAS:
        sc = [b + d * j for b, j in zip(base, jv)]
        per_delta[str(d)] = {"auc": round(auc(sc, labels), 4)}
    per_delta["0.0"] = {"auc": round(auc(base, labels), 4)}

    best_delta = max(DELTAS, key=lambda d: per_delta[str(d)]["auc"])
    sc = [b + best_delta * j for b, j in zip(base, jv)]

    cands = sorted(set(sc))
    grid = [(cands[i] + cands[i + 1]) / 2 for i in range(len(cands) - 1)] or cands
    all_pts = [prf(sc, labels, t) for t in grid]
    tau_f1 = max(all_pts, key=lambda p: p["f1"])
    constrained = [p for p in all_pts if p["fpr"] <= 0.35]
    tau_fpr = max(constrained, key=lambda p: p["f1"]) if constrained else None

    res = {"n": len(rows), "n_joern_vuln": sum(jv),
           "auc_by_delta": per_delta, "DELTA": best_delta,
           "TAU_f1max": tau_f1, "TAU_fpr35": tau_fpr,
           "note": "사전 등록 — report 결과를 보고 변경하지 않는다"}
    (OUT / "joern_tune_selection.json").write_text(json.dumps(res, ensure_ascii=False, indent=1))
    print(json.dumps(res, ensure_ascii=False, indent=1))
    return res


# ── ② report/sample: precision 게이트 ──────────────────────────────────────

def gate_for(rows: list[dict]) -> dict:
    n = len(rows)
    jv = [r for r in rows if r["joern_verdict"] == "vuln"]
    unk = [r for r in rows if r["joern_verdict"] == "unknown"]
    hits = sum(1 for r in jv if r["label"] == "vuln")
    prec = hits / len(jv) if jv else float("nan")
    ci = boot_ci(hits, len(jv)) if jv else [float("nan")] * 2
    unk_rate = len(unk) / n if n else float("nan")

    # 자체 graph 동일 표본 병기
    gv = [r for r in rows if r.get("graph_verdict") == "vuln"]
    ghits = sum(1 for r in gv if r["label"] == "vuln")

    verdict = _verdict(len(jv), prec, ci[0], unk_rate)
    return {
        "n": n, "joern_vuln": len(jv), "joern_safe": n - len(jv) - len(unk),
        "joern_unknown": len(unk), "unknown_rate": round(unk_rate, 4),
        "precision": round(prec, 4) if jv else None, "precision_ci95": ci,
        "graph_vuln": len(gv),
        "graph_precision": round(ghits / len(gv), 4) if gv else None,
        "parse_fail": sum(1 for r in unk if r.get("unknown_reason") == "parse_fail"),
        "timeout": sum(1 for r in unk if r.get("unknown_reason") == "timeout"),
        "wrap1_used": sum(1 for r in rows if r.get("wrap_level") == 1),
        "verdict": verdict,
    }


GRAPH_UNKNOWN_BASELINE = 0.916   # ABLATION_RESULTS.md §2-0


def _verdict(n_vuln: int, prec: float, ci_lo: float, unk_rate: float) -> str:
    if n_vuln < 20:
        return "INCONCLUSIVE"
    if prec >= 0.60 and ci_lo >= 0.80:
        return "TRUST-JOERN"
    if prec >= 0.60:
        return "JOERN-AS-SIGNAL"
    if prec < 0.60 or unk_rate >= GRAPH_UNKNOWN_BASELINE:
        return "JOERN-NO-BETTER"
    return "INCONCLUSIVE"


def run_gate(split: str) -> dict:
    rows = load(split)
    res = {"split": split, "overall": gate_for(rows), "by_lang": {}}
    for lang in sorted({r["lang"] for r in rows}):
        sub = [r for r in rows if r["lang"] == lang]
        g = gate_for(sub)
        pf = g["parse_fail"] / g["n"] if g["n"] else 0
        g["parse_fail_rate"] = round(pf, 4)
        g["excluded_parse_fail_gt_30pct"] = pf > 0.30
        res["by_lang"][lang] = g
    langs_ok = [l for l, g in res["by_lang"].items() if not g["excluded_parse_fail_gt_30pct"]]
    if not langs_ok:
        res["overall"]["verdict"] = "INCONCLUSIVE (파싱 불가 — 전 언어 parse_fail > 30%)"
    res["languages_in_scope"] = langs_ok
    (OUT / f"joern_gate_{split}.json").write_text(json.dumps(res, ensure_ascii=False, indent=1))
    print(json.dumps(res, ensure_ascii=False, indent=1))
    return res


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "tune"
    if mode == "tune":
        run_tune()
    else:
        run_gate(sys.argv[2] if len(sys.argv) > 2 else "sample")
