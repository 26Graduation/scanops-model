"""
Phase 1 판정 — arm 별 지표와 사전등록 게이트 (사양 DIFF_AWARE_RUN_SPEC.md §6·§7)
==================================================================================
쌍 = 같은 `pair_id` 의 두 항목(Version A 판정 1건 + Version B 판정 1건).
순위 정확도 = P(취약 라벨 항목의 점수 > 안전 라벨 항목의 점수).

두 방식으로 보고한다 (§6):
  strict — 동점을 **오답**으로 센다 (보수적)
  tie05  — 동점을 0.5 로 센다 (관례적)

자명 기준선도 같이 낸다: 전량취약 F1, **길이만 쓰는 분류기 AUC**.

실행: python3 rebuild/dw_analyze.py
출력: out/dw_metrics.json
"""
from __future__ import annotations

import json
import random
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from bench_common import score            # noqa: E402
from sweep_threshold import apply_tau, auc  # noqa: E402

ARMS = ["P0", "P1", "P2", "P3", "P1shuf", "P3shuf"]
REG = [("test", "내부 test 100"), ("cybernative154", "CyberNative 50")]
REG_ARMS = ["P0", "P1", "P2"]
N_BOOT, SEED = 2000, 42
CODE = re.compile(r"```[^\n]*\n(.*?)\n```", re.S)

# §7 게이트
WIN_RANK, WIN_TIE, PARTIAL_RANK, SHUF_MAX, REG_TOL = 0.60, 0.10, 0.53, 0.55, -0.02


def load(tag: str, split: str) -> list[dict] | None:
    p = ROOT / "out" / f"{tag}_logprob_{split}.jsonl"
    return [json.loads(l) for l in p.open()] if p.exists() else None


def pairs_of(recs: list[dict]) -> list[dict]:
    g = defaultdict(dict)
    for r in recs:
        g[r["meta"]["pair_id"]][r["meta"]["label"]] = r
    out = []
    for pid, v in g.items():
        if "vuln" in v and "safe" in v:
            out.append({"pid": pid, "bench": v["vuln"]["meta"].get("bench"),
                        "v": v["vuln"]["score"], "s": v["safe"]["score"]})
    return out


def rank_metrics(ps: list[dict]) -> dict:
    if not ps:
        return {}
    win = sum(1 for p in ps if p["v"] > p["s"])
    tie = sum(1 for p in ps if p["v"] == p["s"])
    return {"n_pairs": len(ps),
            "rank_acc_strict": round(win / len(ps), 4),
            "rank_acc_tie05": round((win + 0.5 * tie) / len(ps), 4),
            "tie_rate": round(tie / len(ps), 4)}


def boot_rank(ps: list[dict], n: int = N_BOOT, seed: int = SEED) -> dict:
    rng = random.Random(seed)
    st, t5 = [], []
    for _ in range(n):
        s = [ps[rng.randrange(len(ps))] for _ in range(len(ps))]
        w = sum(1 for p in s if p["v"] > p["s"])
        ti = sum(1 for p in s if p["v"] == p["s"])
        st.append(w / len(s)); t5.append((w + 0.5 * ti) / len(s))
    st.sort(); t5.sort()
    lo, hi = int(n * .025), int(n * .975)
    return {"strict_ci95": [round(st[lo], 4), round(st[hi], 4)],
            "tie05_ci95": [round(t5[lo], 4), round(t5[hi], 4)]}


def length_auc(recs: list[dict], prompts: list[dict]) -> float:
    """길이만 쓰는 자명 기준선 — 판정 대상 코드 길이(짧을수록 취약)."""
    out = []
    for r, p in zip(recs, prompts):
        m = CODE.search(p["prompt"])
        out.append({"meta": r["meta"], "score": -(len(m.group(1)) if m else len(p["prompt"]))})
    return auc(out)


def main() -> None:
    res: dict = {"spec": "rebuild/DIFF_AWARE_RUN_SPEC.md", "n_boot": N_BOOT,
                 "arms": {}, "regression": {}, "verdict": {}}

    for arm in ARMS:
        recs = load("dw", f"dw_{arm}")
        if recs is None:
            res["arms"][arm] = {"status": "미실행"}
            print(f"[{arm}] 미실행")
            continue
        prompts = [json.loads(l) for l in (ROOT / "data" / f"dw_{arm}.jsonl").open()]
        ps = pairs_of(recs)
        e = {**rank_metrics(ps), **boot_rank(ps), "auc": auc(recs), "n_items": len(recs),
             "trivial_all_vuln_f1": score([{"meta": r["meta"], "label": "vuln"} for r in recs])["f1"],
             "auc_length_only": length_auc(recs, prompts),
             "by_bench": {}}
        for b in sorted({p["bench"] for p in ps if p["bench"]}):
            sub = [p for p in ps if p["bench"] == b]
            e["by_bench"][b] = {**rank_metrics(sub), **boot_rank(sub)}
        res["arms"][arm] = e
        print(f"[{arm:7s}] 쌍 {e['n_pairs']:3d}  순위(엄격) {e['rank_acc_strict']} "
              f"{e['strict_ci95']}  동점 {e['tie_rate']}  AUC {e['auc']} "
              f"(길이만 {e['auc_length_only']})")
        for b, v in e["by_bench"].items():
            print(f"          └ {b:10s} n={v['n_pairs']:3d} 순위 {v['rank_acc_strict']} {v['strict_ci95']} 동점 {v['tie_rate']}")

    # ── 단건 회귀 ────────────────────────────────────────────────────────
    for split, label in REG:
        res["regression"][split] = {}
        base = None
        for arm in REG_ARMS:
            recs = load("dw", f"dw_reg_{split}_{arm}")
            if recs is None:
                res["regression"][split][arm] = {"status": "미실행"}
                continue
            a = auc(recs)
            if arm == "P0":
                base = a
            res["regression"][split][arm] = {
                "auc": a, "n": len(recs),
                "delta_vs_P0": None if base is None else round(a - base, 4),
                "pass": None if base is None else (a - base) >= REG_TOL}
            print(f"[회귀 {label} / {arm}] AUC {a}"
                  + ("" if base is None or arm == "P0"
                     else f"  Δ vs P0 {a-base:+.4f}  {'통과' if (a-base)>=REG_TOL else '실패'}"))

    # ── 사전등록 판정 (§7) ───────────────────────────────────────────────
    shuf_of = {"P1": "P1shuf", "P3": "P3shuf"}
    cand = {}
    for arm in ("P0", "P1", "P2", "P3"):
        e = res["arms"].get(arm)
        if not e or "rank_acc_strict" not in e:
            continue
        sh = res["arms"].get(shuf_of.get(arm, ""), {})
        shuf_val = sh.get("rank_acc_strict")
        shuf_ok = True if shuf_val is None else shuf_val <= SHUF_MAX
        reg_ok = all(res["regression"].get(s, {}).get(arm, {}).get("pass", True) is not False
                     for s, _ in REG) if arm in REG_ARMS else None
        cand[arm] = {"rank_acc_strict": e["rank_acc_strict"], "tie_rate": e["tie_rate"],
                     "shuf_arm": shuf_of.get(arm), "shuf_rank_acc": shuf_val,
                     "shuf_ok": shuf_ok, "regression_ok": reg_ok,
                     "invalidated_by_shuf": not shuf_ok}
    valid = {k: v for k, v in cand.items() if v["shuf_ok"] and k != "P0"}
    best = max(valid, key=lambda k: valid[k]["rank_acc_strict"], default=None)
    gate = "PROMPT-NULL"
    if best:
        b = valid[best]
        if (b["rank_acc_strict"] >= WIN_RANK and b["tie_rate"] <= WIN_TIE
                and b["regression_ok"] is not False):
            gate = "PROMPT-WIN"
        elif b["rank_acc_strict"] >= PARTIAL_RANK:
            gate = "PROMPT-PARTIAL"
    res["verdict"] = {"gate": gate, "best_arm": best, "candidates": cand,
                      "baseline_P0_rank_acc": cand.get("P0", {}).get("rank_acc_strict"),
                      "rule": "§7 — WIN ≥0.60 & 동점 ≤0.10 & 회귀통과 & shuf ≤0.55 / "
                              "PARTIAL 0.53~0.60 / NULL <0.53. shuf >0.55 인 arm 은 제외"}
    p = ROOT / "out" / "dw_metrics.json"
    p.write_text(json.dumps(res, ensure_ascii=False, indent=2))
    print(f"\n판정: {gate}   최고 arm: {best}   (P0 기준선 {res['verdict']['baseline_P0_rank_acc']})")
    print(f"→ {p}")


if __name__ == "__main__":
    main()
