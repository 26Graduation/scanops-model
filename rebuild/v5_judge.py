"""
V5 판정 — 사양 V5_TRAIN_RUN_SPEC.md §5 + §10, 결정 로그 D-28 의 2×2 대조
==========================================================================
쌍 지표는 전부 **위치 상쇄**(배정 X: 취약본=A / Y: 취약본=B)로 낸다 —
Phase 1 에서 상쇄 없이 재면 위치 편향을 능력으로 오독한다는 것이 드러났다(D-27).

주 대조 (D-28, 결과 전 고정):
  형식 학습 기여   v5+P2  vs  v3s42@750+P2   (추론 형식을 맞춰 학습만 비교)
  형식 전체 효과   v5+P2  vs  v3s42@750+P0
  형식 전이        v5+P0  vs  v3s42@750+P0
  제품 관점        v5+P2  vs  v1+P2

실행: python3 rebuild/v5_judge.py [tag]     (기본 v5)
출력: out/v5_metrics.json
"""
from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from sweep_threshold import apply_tau, auc  # noqa: E402
from bench_common import score              # noqa: E402

TAG = sys.argv[1] if len(sys.argv) > 1 else "v5"
N_BOOT, SEED = 2000, 42
ADOPT_RANK, POS_GAP_MAX, REG_TOL, FPR_TOL = 0.60, 0.20, -0.02, 0.05
BENCH = ["test", "cleanvul_v2_report", "cleanvul_v2_tune", "primevul_report",
         "cvefixes157", "cybernative154"]


def load(tag: str, name: str) -> list[dict] | None:
    p = ROOT / "out" / f"{tag}_logprob_{name}.jsonl"
    return [json.loads(l) for l in p.open()] if p.exists() else None


def pairs(recs: list[dict]) -> dict:
    g = defaultdict(dict)
    for r in recs:
        g[r["meta"]["pair_id"]][r["meta"]["label"]] = r
    return {k: v for k, v in g.items() if "vuln" in v and "safe" in v}


def acc(pp: dict, ks: list[str]) -> float:
    return sum(1 for k in ks if pp[k]["vuln"]["score"] > pp[k]["safe"]["score"]) / len(ks)


def tie(pp: dict, ks: list[str]) -> float:
    return sum(1 for k in ks if pp[k]["vuln"]["score"] == pp[k]["safe"]["score"]) / len(ks)


def cb_of(tag: str, fmt: str) -> tuple[dict, dict] | None:
    X, Y = load(tag, f"dw_cbX_{fmt}"), load(tag, f"dw_cbY_{fmt}")
    return (pairs(X), pairs(Y)) if X and Y else None


def fpr_safe(tag: str, fmt: str) -> float | None:
    """안전 판본만 모아 τ=0 에서 '취약'이라 답한 비율 (사양 §4 FPR-safe)."""
    recs = []
    for a in ("cbX", "cbY"):
        r = load(tag, f"dw_{a}_{fmt}")
        if r:
            recs += [x for x in r if x["meta"]["label"] == "safe"]
    if not recs:
        return None
    return round(sum(1 for x in apply_tau(recs, 0.0) if x["label"] == "vuln") / len(recs), 4)


def main() -> None:
    out: dict = {"spec": "rebuild/V5_TRAIN_RUN_SPEC.md §5·§10, D-28", "tag": TAG,
                 "pair_cb": {}, "contrasts": {}, "bench_auc": {}, "fpr_safe": {}}

    # ── 쌍 지표 (상쇄) ───────────────────────────────────────────────────
    cells = {}
    for tag in (TAG, "v3s42dw", "dw"):          # dw = v1
        label = {"v3s42dw": "v3s42@750", "dw": "v1"}.get(tag, TAG)
        for fmt in ("P2", "P0"):
            if fmt == "P0":
                r = load(tag, "dw_P0")
                if not r:
                    continue
                pp = pairs(r); ks = sorted(pp)
                cells[(label, "P0")] = {"acc_cb": round(acc(pp, ks), 4), "pos_gap": None,
                                        "tie": round(tie(pp, ks), 4), "n": len(ks)}
            else:
                c = cb_of(tag, fmt)
                if not c:
                    continue
                px, py = c
                ks = sorted(set(px) & set(py))
                ax, ay = acc(px, ks), acc(py, ks)
                cells[(label, fmt)] = {"acc_cb": round((ax + ay) / 2, 4),
                                       "acc_X": round(ax, 4), "acc_Y": round(ay, 4),
                                       "pos_gap": round(abs(ax - ay), 4),
                                       "tie": round(max(tie(px, ks), tie(py, ks)), 4),
                                       "n": len(ks)}
    out["pair_cb"] = {f"{a}|{b}": v for (a, b), v in cells.items()}
    print("=== 쌍 지표 (위치 상쇄) ===")
    for (a, b), v in cells.items():
        print(f"  {a:12s} {b}: acc_cb {v['acc_cb']}  gap {v['pos_gap']}  동점 {v['tie']}  n={v['n']}")

    # ── 대조 (쌍 부트스트랩) ─────────────────────────────────────────────
    def delta(na, fa, nb, fb, name):
        def get(n, f):
            if f == "P0":
                r = load({"v3s42@750": "v3s42dw", "v1": "dw"}.get(n, TAG), "dw_P0")
                return ("single", pairs(r)) if r else None
            c = cb_of({"v3s42@750": "v3s42dw", "v1": "dw"}.get(n, TAG), f)
            return ("cb", c) if c else None
        A, B = get(na, fa), get(nb, fb)
        if not A or not B:
            out["contrasts"][name] = {"status": "미실행"}
            return
        keys = None
        for kind, obj in (A, B):
            s = set(obj) if kind == "single" else set(obj[0]) & set(obj[1])
            keys = s if keys is None else keys & s
        keys = sorted(keys)
        f = lambda x, ks: acc(x[1], ks) if x[0] == "single" else (acc(x[1][0], ks) + acc(x[1][1], ks)) / 2
        rng = random.Random(SEED); ds = []
        for _ in range(N_BOOT):
            s = [keys[rng.randrange(len(keys))] for _ in keys]
            ds.append(f(A, s) - f(B, s))
        ds.sort()
        pt = f(A, keys) - f(B, keys)
        out["contrasts"][name] = {"a": f"{na}+{fa}", "b": f"{nb}+{fb}", "n": len(keys),
                                  "delta": round(pt, 4),
                                  "ci95": [round(ds[int(N_BOOT*.025)], 4), round(ds[int(N_BOOT*.975)], 4)],
                                  "ci_lower_gt_0": ds[int(N_BOOT*.025)] > 0}
        c = out["contrasts"][name]
        print(f"  {name:24s} {c['a']} − {c['b']} = {c['delta']:+.4f}  CI {c['ci95']}  하한>0 {c['ci_lower_gt_0']}")

    print("\n=== 대조 (D-28) ===")
    delta(TAG, "P2", "v3s42@750", "P2", "형식 학습 기여")
    delta(TAG, "P2", "v3s42@750", "P0", "형식 전체 효과")
    delta(TAG, "P0", "v3s42@750", "P0", "형식 전이")
    delta(TAG, "P2", "v1", "P2", "제품 관점(v1 대비)")

    # ── 벤치 AUC + FPR-safe ─────────────────────────────────────────────
    print("\n=== 벤치 AUC (P0 형식, 참고) ===")
    for b in BENCH:
        r = load(TAG, b)
        if r:
            out["bench_auc"][b] = auc(r)
            print(f"  {b:22s} {auc(r)}")
    for tag, lab in ((TAG, TAG), ("dw", "v1"), ("v3s42dw", "v3s42@750")):
        v = fpr_safe(tag, "P2")
        if v is not None:
            out["fpr_safe"][lab] = v
    print(f"\nFPR-safe (P2, τ=0): {out['fpr_safe']}")

    # ── 판정 ─────────────────────────────────────────────────────────────
    me = cells.get((TAG, "P2"))
    v1p2 = cells.get(("v1", "P2"))
    fs, fs1 = out["fpr_safe"].get(TAG), out["fpr_safe"].get("v1")
    conds = {
        "rank_cb>=0.60": me and me["acc_cb"] >= ADOPT_RANK,
        "pos_gap<=0.20": me and me["pos_gap"] is not None and me["pos_gap"] <= POS_GAP_MAX,
        "학습기여 CI하한>0": out["contrasts"].get("형식 학습 기여", {}).get("ci_lower_gt_0"),
        "FPR-safe<=v1+0.05": (fs is not None and fs1 is not None and fs <= fs1 + FPR_TOL),
    }
    out["adopt_conditions"] = conds
    out["verdict"] = "ADOPT-PR" if all(conds.values()) else "NO-ADOPT"
    p = ROOT / "out" / f"{TAG}_metrics.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"\n조건: {conds}")
    print(f"판정: {out['verdict']}")
    print(f"→ {p}")


if __name__ == "__main__":
    main()
