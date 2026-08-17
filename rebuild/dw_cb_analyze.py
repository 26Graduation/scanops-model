"""
위치 상쇄 판정 (사양 DIFF_AWARE_RUN_SPEC.md §10-3)
====================================================
배정 X(취약본=Version A) 와 배정 Y(취약본=Version B) 를 따로 채점하고
  acc_cb  = (acc_X + acc_Y) / 2      ← 주 지표. 더해지는 위치 항이 상쇄된다
  pos_gap = |acc_X − acc_Y|          ← 형식이 만든 위치 편향의 크기
를 낸다.

판정: CB-WIN(acc_cb ≥ 0.60 & pos_gap ≤ 0.20 & 동점 ≤ 0.10 & shuf ≤ 0.55)
      CB-PARTIAL(0.53~0.60 & pos_gap ≤ 0.20) / CB-NULL(그 외.
      **pos_gap > 0.20 이면 acc_cb 가 높아도 여기로 간다**)

실행: python3 rebuild/dw_cb_analyze.py
출력: out/dw_cb_metrics.json
"""
from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

ARMS = ["P1", "P2", "P3"]
N_BOOT, SEED = 2000, 42
CB_WIN, CB_PARTIAL, POS_GAP_MAX, TIE_MAX, SHUF_MAX = 0.60, 0.53, 0.20, 0.10, 0.55


def load(name: str) -> list[dict] | None:
    p = ROOT / "out" / f"dw_logprob_dw_{name}.jsonl"
    return [json.loads(l) for l in p.open()] if p.exists() else None


def pairs(recs: list[dict]) -> dict[str, dict]:
    g = defaultdict(dict)
    for r in recs:
        g[r["meta"]["pair_id"]][r["meta"]["label"]] = r
    return {k: v for k, v in g.items() if "vuln" in v and "safe" in v}


def acc_tie(pp: dict, keys: list[str]) -> tuple[float, float]:
    win = sum(1 for k in keys if pp[k]["vuln"]["score"] > pp[k]["safe"]["score"])
    tie = sum(1 for k in keys if pp[k]["vuln"]["score"] == pp[k]["safe"]["score"])
    return win / len(keys), tie / len(keys)


def main() -> None:
    res: dict = {"spec": "rebuild/DIFF_AWARE_RUN_SPEC.md §10-3", "n_boot": N_BOOT, "arms": {}}
    prev = json.load((ROOT / "out" / "dw_metrics.json").open())

    for arm in ARMS:
        X, Y = load(f"cbX_{arm}"), load(f"cbY_{arm}")
        if X is None or Y is None:
            res["arms"][arm] = {"status": "미실행"}
            print(f"[{arm}] 미실행")
            continue
        px, py = pairs(X), pairs(Y)
        keys = sorted(set(px) & set(py))
        ax, tx = acc_tie(px, keys)
        ay, ty = acc_tie(py, keys)
        cb, gap = (ax + ay) / 2, abs(ax - ay)

        rng = random.Random(SEED)
        cbs, gaps = [], []
        for _ in range(N_BOOT):
            s = [keys[rng.randrange(len(keys))] for _ in keys]
            a1, _ = acc_tie(px, s)
            a2, _ = acc_tie(py, s)
            cbs.append((a1 + a2) / 2); gaps.append(abs(a1 - a2))
        cbs.sort(); gaps.sort()
        lo, hi = int(N_BOOT * .025), int(N_BOOT * .975)

        shuf = prev["arms"].get(f"{arm}shuf", {}).get("rank_acc_strict")
        e = {"n_pairs": len(keys),
             "acc_X_vuln_is_A": round(ax, 4), "acc_Y_vuln_is_B": round(ay, 4),
             "acc_cb": round(cb, 4), "acc_cb_ci95": [round(cbs[lo], 4), round(cbs[hi], 4)],
             "pos_gap": round(gap, 4), "pos_gap_ci95": [round(gaps[lo], 4), round(gaps[hi], 4)],
             "tie_rate_X": round(tx, 4), "tie_rate_Y": round(ty, 4),
             "shuf_rank_acc": shuf,
             "phase1_uncounterbalanced": prev["arms"].get(arm, {}).get("rank_acc_strict"),
             "by_bench": {}}
        for b in sorted({px[k]["vuln"]["meta"]["bench"] for k in keys}):
            ks = [k for k in keys if px[k]["vuln"]["meta"]["bench"] == b]
            a1, _ = acc_tie(px, ks); a2, _ = acc_tie(py, ks)
            e["by_bench"][b] = {"n": len(ks), "acc_X": round(a1, 4), "acc_Y": round(a2, 4),
                                "acc_cb": round((a1 + a2) / 2, 4), "pos_gap": round(abs(a1 - a2), 4)}

        tie_ok = max(tx, ty) <= TIE_MAX
        shuf_ok = shuf is None or shuf <= SHUF_MAX
        if gap > POS_GAP_MAX:
            v = "CB-NULL"
        elif cb >= CB_WIN and tie_ok and shuf_ok:
            v = "CB-WIN"
        elif cb >= CB_PARTIAL:
            v = "CB-PARTIAL"
        else:
            v = "CB-NULL"
        e["verdict"] = v
        res["arms"][arm] = e
        print(f"[{arm}] acc_X(취약=A) {ax:.4f}  acc_Y(취약=B) {ay:.4f}  "
              f"→ acc_cb {cb:.4f} {e['acc_cb_ci95']}  pos_gap {gap:.4f}  "
              f"동점 {max(tx,ty):.4f}  → {v}   (Phase1 비상쇄 {e['phase1_uncounterbalanced']})")
        for b, v2 in e["by_bench"].items():
            print(f"      └ {b:10s} n={v2['n']:3d}  X {v2['acc_X']:.4f} / Y {v2['acc_Y']:.4f} "
                  f"→ cb {v2['acc_cb']:.4f}  gap {v2['pos_gap']:.4f}")

    ok = {a: e for a, e in res["arms"].items() if e.get("verdict") in ("CB-WIN", "CB-PARTIAL")}
    best = max(ok, key=lambda a: ok[a]["acc_cb"], default=None)
    res["final"] = {"best_arm": best,
                    "gate": ok[best]["verdict"] if best else "CB-NULL",
                    "rule": "CB-WIN ≥0.60 & pos_gap ≤0.20 & 동점 ≤0.10 & shuf ≤0.55 / "
                            "CB-PARTIAL 0.53~0.60 & pos_gap ≤0.20 / 그 외 CB-NULL"}
    p = ROOT / "out" / "dw_cb_metrics.json"
    p.write_text(json.dumps(res, ensure_ascii=False, indent=2))
    print(f"\n최종: {res['final']['gate']}  최고 arm: {best}")
    print(f"→ {p}")


if __name__ == "__main__":
    main()
