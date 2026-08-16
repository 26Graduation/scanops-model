"""
OPPOINT-OP — 운영점 재보정 (사양서 rebuild/OPPOINT_RUN_SPEC.md §8)
==================================================================
질문: 배포 경로(_detect greedy = τ 0 암묵적)가 최선의 운영점인가.
      아니라면 어느 τ 가 배포에 적합한가.

프로토콜(사양 §8-3):
  τ 는 **tune 소스에서만** 고른다 — CleanVul_v2 tune(도메인 밖) + 내부 val(도메인 안).
  두 소스를 합쳐 세지 않는다(크기 큰 쪽이 지배하므로).
  목적함수 = 두 소스 F1 의 **평균**, 제약(FPR) 은 **두 소스 모두**에서 만족.
  고른 τ 는 보고 split 에 **1회씩만** 적용한다.

비용 $0 — 기존 logprob 산출물만 읽는다.
실행: python3 rebuild/oppoint_op.py [tag] [val_split]
      예) python3 rebuild/oppoint_op.py v1 val
출력: out/oppoint_op_{tag}.json
"""
from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from bench_common import score              # noqa: E402  — 지표 정의 재사용
from sweep_threshold import apply_tau, auc   # noqa: E402

SEED = 42
N_BOOT = 2000

TAG = sys.argv[1] if len(sys.argv) > 1 else "v1"
VAL = sys.argv[2] if len(sys.argv) > 2 else "val"

# 사양 §8-3 — τ 선정에 쓰는 소스는 이 둘뿐
TUNE_SOURCES = [("cleanvul_v2_tune", "도메인 밖"), (VAL, "도메인 안")]
# 사양 §8-5 — 보고 split. 없는 파일은 건너뛰고 "미실행"으로 기록한다
REPORT_SPLITS = [
    ("test",                "내부 test",            "도메인 안"),
    ("cleanvul_v2_report",  "CleanVul_v2 report",   "도메인 밖 (주)"),
    ("primevul_report",     "PrimeVul report",      "도메인 밖"),
    ("cvefixes157",         "CVEfixes 157",         "도메인 밖"),
    ("cybernative154",      "CyberNative 154",      "도메인 밖 (독립 출처)"),
]
# 사양 §8-4
FPR_CAPS = {"OP-B": 0.15, "OP-C": 0.10}
# 사양 §8-6
GATE_TEST_RECALL, GATE_TEST_FPR = 0.75, 0.15


def load(split: str) -> list[dict]:
    p = ROOT / "out" / f"{TAG}_logprob_{split}.jsonl"
    return [json.loads(l) for l in p.open()] if p.exists() else []


def units(items: list[dict]) -> list[list[dict]]:
    """쌍 데이터는 쌍째로 재표집 — bootstrap_ci.py 와 동일 규약."""
    if items and items[0]["meta"].get("pair_id"):
        g = defaultdict(list)
        for r in items:
            g[r["meta"]["pair_id"]].append(r)
        return list(g.values())
    return [[r] for r in items]


def trivial(recs: list[dict]) -> dict:
    """자명 기준선 '전량 취약' — 균형셋에서 F1 0.667 이 공짜로 나온다."""
    return score([{"meta": r["meta"], "label": "vuln"} for r in recs])


# ── τ 후보 격자 ─────────────────────────────────────────────────────────────
def tau_grid(sources: dict[str, list[dict]], n_each: int = 400) -> list[float]:
    """두 tune 소스의 점수 분위를 합집합으로. τ=0(현 배포 지점)은 반드시 포함."""
    xs: set[float] = {0.0}
    for recs in sources.values():
        v = sorted({round(r["score"], 4) for r in recs})
        step = max(1, len(v) // n_each)
        xs.update(v[::step])
        xs.update([v[0] - 1.0, v[-1] + 1.0])
    return sorted(xs)


def select_ops(sources: dict[str, list[dict]]) -> tuple[dict, list[dict]]:
    """사양 §8-4 의 OP-0/A/B/C 를 tune 에서만 고른다."""
    grid = tau_grid(sources)
    rows = []
    for t in grid:
        per = {k: score(apply_tau(v, t)) for k, v in sources.items()}
        rows.append({
            "tau": t,
            "per_source": per,
            "mean_f1": round(sum(s["f1"] for s in per.values()) / len(per), 6),
            "max_fpr": round(max(s["fpr"] for s in per.values()), 6),
        })

    ops: dict = {}
    # OP-0 — 현 배포와 같은 지점(τ=0). 고르는 게 아니라 고정이다.
    ops["OP-0"] = {"tau": 0.0, "rule": "τ=0 (현 배포 greedy 와 동일 지점). 기준선",
                   "feasible": True}
    # OP-A — 제약 없음, 평균 F1 최대
    best = max(rows, key=lambda r: (r["mean_f1"], -abs(r["tau"])))
    ops["OP-A"] = {"tau": best["tau"], "rule": "두 tune 소스 평균 F1 최대 (제약 없음)",
                   "feasible": True}
    # OP-B / OP-C — FPR 상한 제약(두 소스 모두)
    for name, cap in FPR_CAPS.items():
        ok = [r for r in rows if r["max_fpr"] <= cap]
        if not ok:
            ops[name] = {"tau": None, "rule": f"두 소스 모두 FPR ≤ {cap} 아래 평균 F1 최대",
                         "feasible": False, "note": "INFEASIBLE — 제약을 만족하는 τ 없음. 완화하지 않는다"}
            continue
        b = max(ok, key=lambda r: (r["mean_f1"], -abs(r["tau"])))
        ops[name] = {"tau": b["tau"], "rule": f"두 소스 모두 FPR ≤ {cap} 아래 평균 F1 최대",
                     "feasible": True}

    # 선정 근거를 남긴다 — 고른 τ 에서의 tune 지표
    by_tau = {r["tau"]: r for r in rows}
    for name, o in ops.items():
        if o["tau"] is not None and o["tau"] in by_tau:
            r = by_tau[o["tau"]]
            o["tune_at_tau"] = {k: v for k, v in r["per_source"].items()}
            o["tune_mean_f1"] = r["mean_f1"]
            o["tune_max_fpr"] = r["max_fpr"]
    return ops, rows


# ── 부트스트랩 ──────────────────────────────────────────────────────────────
def boot_ci(recs: list[dict], tau: float, n: int = N_BOOT, seed: int = SEED) -> dict:
    us = units(apply_tau(recs, tau))
    rng = random.Random(seed)
    p, r, f = [], [], []
    for _ in range(n):
        samp = [x for _ in range(len(us)) for x in rng.choice(us)]
        s = score(samp)
        p.append(s["precision"]); r.append(s["recall"]); f.append(s["f1"])
    for a in (p, r, f):
        a.sort()
    lo, hi = int(n * 0.025), int(n * 0.975)
    return {"precision_ci95": [round(p[lo], 4), round(p[hi], 4)],
            "recall_ci95": [round(r[lo], 4), round(r[hi], 4)],
            "f1_ci95": [round(f[lo], 4), round(f[hi], 4)]}


def paired_delta_precision(recs: list[dict], tau_a: float, tau_b: float,
                           n: int = N_BOOT, seed: int = SEED) -> dict:
    """같은 재표집에 두 운영점을 함께 태워 Δprecision 분포를 본다(대응 표본)."""
    ua, ub = units(apply_tau(recs, tau_a)), units(apply_tau(recs, tau_b))
    assert len(ua) == len(ub)
    rng = random.Random(seed)
    ds = []
    for _ in range(n):
        idx = [rng.randrange(len(ua)) for _ in range(len(ua))]
        sa = score([x for i in idx for x in ua[i]])
        sb = score([x for i in idx for x in ub[i]])
        ds.append(sa["precision"] - sb["precision"])
    ds.sort()
    lo, hi = int(n * 0.025), int(n * 0.975)
    point = score(apply_tau(recs, tau_a))["precision"] - score(apply_tau(recs, tau_b))["precision"]
    return {"delta_precision": round(point, 4),
            "ci95": [round(ds[lo], 4), round(ds[hi], 4)],
            "ci_lower_gt_0": ds[lo] > 0}


def main() -> None:
    sources = {}
    for name, _ in TUNE_SOURCES:
        recs = load(name)
        if not recs:
            raise SystemExit(f"τ 선정 소스가 없다: out/{TAG}_logprob_{name}.jsonl")
        sources[name] = recs
    print(f"[tune] " + ", ".join(f"{k}={len(v)}" for k, v in sources.items()))

    ops, grid_rows = select_ops(sources)
    for k, o in ops.items():
        print(f"  {k}: tau={o['tau']} feasible={o['feasible']} "
              f"mean_f1={o.get('tune_mean_f1')} max_fpr={o.get('tune_max_fpr')}")

    results: dict = {}
    missing: list[str] = []
    for split, label, kind in REPORT_SPLITS:
        recs = load(split)
        if not recs:
            missing.append(split)
            print(f"[skip] {label} — out/{TAG}_logprob_{split}.jsonl 없음 (미실행으로 기록)")
            continue
        entry = {
            "label": label, "kind": kind, "n": len(recs),
            "auc": auc(recs),
            "trivial_all_vuln": trivial(recs),
            "ops": {},
        }
        for k, o in ops.items():
            if not o["feasible"]:
                entry["ops"][k] = {"INFEASIBLE": True}
                continue
            s = score(apply_tau(recs, o["tau"]))
            s["tau"] = o["tau"]
            s.update(boot_ci(recs, o["tau"]))
            entry["ops"][k] = s
        results[split] = entry
        print(f"[{label}] n={len(recs)} auc={entry['auc']} " +
              " ".join(f"{k}(P={v.get('precision')},R={v.get('recall')},FPR={v.get('fpr')})"
                       for k, v in entry["ops"].items() if "precision" in v))

    # ── 사양 §8-6 판정 ───────────────────────────────────────────────────────
    verdict = {"gate": "OP-INSUFFICIENT", "chosen": None, "per_op": {}}
    cvr = results.get("cleanvul_v2_report")
    tst = results.get("test")
    for k, o in ops.items():
        if k == "OP-0" or not o["feasible"]:
            continue
        c1 = c2 = None
        if tst and "precision" in tst["ops"][k]:
            t = tst["ops"][k]
            c1 = (t["recall"] >= GATE_TEST_RECALL) and (t["fpr"] <= GATE_TEST_FPR)
        if cvr:
            d = paired_delta_precision(load("cleanvul_v2_report"), o["tau"], ops["OP-0"]["tau"])
            c2 = d["ci_lower_gt_0"]
        else:
            d = None
        verdict["per_op"][k] = {
            "cond1_internal_test_recall>=0.75_and_fpr<=0.15": c1,
            "cond2_cleanvul_delta_precision_vs_OP0_ci_lower>0": c2,
            "delta_precision_detail": d,
            "passes": bool(c1) and bool(c2),
        }
    winners = [k for k, v in verdict["per_op"].items() if v["passes"]]
    if winners:
        verdict["gate"] = "OP-CANDIDATE"
        verdict["chosen"] = max(
            winners, key=lambda k: verdict["per_op"][k]["delta_precision_detail"]["ci95"][0])

    out = {
        "spec": "rebuild/OPPOINT_RUN_SPEC.md §8",
        "tag": TAG, "seed": SEED, "n_boot": N_BOOT,
        "tune_sources": {k: len(v) for k, v in sources.items()},
        "ops": ops,
        "results": results,
        "splits_not_scored": missing,
        "verdict": verdict,
    }
    p = ROOT / "out" / f"oppoint_op_{TAG}.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"\n판정: {verdict['gate']}  chosen={verdict['chosen']}")
    print(f"→ {p}")


if __name__ == "__main__":
    main()
