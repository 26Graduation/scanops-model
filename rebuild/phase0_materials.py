"""
Phase 0 — 재료 확인 (비용 $0)
==============================
오늘의 실험(diff 를 보여주면 보는가)에 필요한 재료를 전부 세고, 한계를 먼저 확정한다.

  (a) 유사도 0.95+ 쌍 목록 — 벤치별·언어별 분포, v1 동점 쌍
  (b) 각 쌍의 diff — 변경 줄 수·추가/삭제·위치. **변경 줄 0 인 쌍은 따로 표기**
      (프롬프트에 diff 를 넣어도 넣을 것이 없는 쌍 = 어떤 방법으로도 못 가른다)
  (c) `train_v3` 의 쌍 수와 유사도 분포 — 0.95+ 쌍을 학습에서 **본 적이 있는가**
  (d) 근사 중복 누수 — 학습셋 ↔ 평가 3종을 유사도 ≥ 0.95 로 대조 (어제 미완)

(d) 방법: 전수 비교는 13,406 × 4,191 = 5,600만 쌍이라 불가능하다.
    **줄 단위 3-shingle 역색인**으로 후보를 좁히고(공유 shingle ≥ 1),
    후보에 대해서만 `difflib.SequenceMatcher` 를 돌린다.
    이건 **근사**다 — shingle 을 하나도 공유하지 않는 근사 중복은 놓친다. 그 한계를 결과에 적는다.

실행: python3 rebuild/phase0_materials.py
출력: out/phase0_materials.json, out/phase0_sim95_pairs.jsonl
"""
from __future__ import annotations

import difflib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CODE = re.compile(r"```[^\n]*\n(.*?)\n```", re.S)
TAG = "v1"
EVAL = [("test", "내부test"), ("cleanvul_v2_report", "CleanVul"), ("primevul_report", "PrimeVul")]
SIM_HI = 0.95
SHINGLE_K = 3
LEAK_SIM = 0.95


def pair_key(m: dict) -> str | None:
    return m.get("pair_id") or m.get("cve_id") or None


def code_of(p: str) -> str:
    m = CODE.search(p)
    return m.group(1) if m else p


def norm_lines(code: str) -> list[str]:
    return [re.sub(r"\s+", " ", l).strip() for l in code.splitlines() if l.strip()]


def shingles(code: str, k: int = SHINGLE_K) -> set[int]:
    ls = norm_lines(code)
    if len(ls) < k:
        return {hash(tuple(ls))} if ls else set()
    return {hash(tuple(ls[i:i + k])) for i in range(len(ls) - k + 1)}


def diff_stats(a: str, b: str) -> dict:
    la, lb = a.splitlines(), b.splitlines()
    sm = difflib.SequenceMatcher(None, la, lb)
    add = dele = 0
    first_change = None
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if first_change is None:
            first_change = i1
        if tag in ("replace", "delete"):
            dele += i2 - i1
        if tag in ("replace", "insert"):
            add += j2 - j1
    return {"added": add, "deleted": dele, "changed_lines": add + dele,
            "first_change_line": first_change,
            "n_lines_a": len(la), "n_lines_b": len(lb)}


def load(split: str) -> tuple[list[dict], list[dict]]:
    sc = [json.loads(l) for l in (ROOT / "out" / f"{TAG}_logprob_{split}.jsonl").open()]
    da = [json.loads(l) for l in (ROOT / "data" / f"{split}.jsonl").open()]
    assert len(sc) == len(da), f"{split}: 길이 불일치"
    return sc, da


def main() -> None:
    out: dict = {"sim_threshold": SIM_HI, "benches": {}, "train": {}, "leakage": {}}
    rows_out = []

    # ── (a)(b) 평가셋 0.95+ 쌍 ────────────────────────────────────────────
    for split, name in EVAL:
        sc, da = load(split)
        g = defaultdict(lambda: defaultdict(list))
        for s, d in zip(sc, da):
            k = pair_key(s["meta"])
            if k:
                g[k][s["meta"]["label"]].append(
                    (s["score"], code_of(d["prompt"]), s["meta"].get("lang_group")))
        hi, all_pairs = [], 0
        for k, v in g.items():
            if len(v.get("vuln", [])) != 1 or len(v.get("safe", [])) != 1:
                continue
            all_pairs += 1
            (sv, cv, lg), (ss, cs, _) = v["vuln"][0], v["safe"][0]
            sim = difflib.SequenceMatcher(None, cv, cs).ratio()
            if sim < SIM_HI:
                continue
            ds = diff_stats(cv, cs)
            row = {"bench": name, "split": split, "case_id": k, "lang": lg,
                   "sim": round(sim, 4), "score_vuln": sv, "score_safe": ss,
                   "correct": sv > ss, "tie": sv == ss, **ds}
            hi.append(row)
            rows_out.append(row)
        zero = [r for r in hi if r["changed_lines"] == 0]
        out["benches"][name] = {
            "split": split, "n_pairs_total": all_pairs, "n_pairs_sim95": len(hi),
            "rank_acc": round(sum(r["correct"] for r in hi) / len(hi), 4) if hi else None,
            "tie_rate": round(sum(r["tie"] for r in hi) / len(hi), 4) if hi else None,
            "by_lang": dict(Counter(r["lang"] for r in hi)),
            "changed_lines_median": sorted(r["changed_lines"] for r in hi)[len(hi) // 2] if hi else None,
            "n_changed_lines_zero": len(zero),
            "zero_change_case_ids": [r["case_id"] for r in zero][:20],
            "n_tie": sum(r["tie"] for r in hi),
        }
        print(f"[{name:10s}] 0.95+ 쌍 {len(hi):5d}/{all_pairs:5d}  "
              f"순위 {out['benches'][name]['rank_acc']}  동점 {out['benches'][name]['tie_rate']}  "
              f"변경줄 중앙값 {out['benches'][name]['changed_lines_median']}  "
              f"변경0 {len(zero)}건  언어 {out['benches'][name]['by_lang']}")

    out["total_sim95_pairs"] = len(rows_out)
    with (ROOT / "out" / "phase0_sim95_pairs.jsonl").open("w") as f:
        for r in rows_out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # ── (c) 학습셋 쌍 유사도 분포 ─────────────────────────────────────────
    tr = [json.loads(l) for l in (ROOT / "data" / "train_v3.jsonl").open()]
    g = defaultdict(lambda: defaultdict(list))
    for r in tr:
        k = pair_key(r["meta"])
        if k:
            g[k][r["meta"]["label"]].append(code_of(r["prompt"]))
    sims = []
    for v in g.values():
        if len(v.get("vuln", [])) != 1 or len(v.get("safe", [])) != 1:
            continue
        sims.append(difflib.SequenceMatcher(None, v["vuln"][0], v["safe"][0]).ratio())
    bins = [(0, .3), (.3, .6), (.6, .85), (.85, .95), (.95, 1.01)]
    out["train"] = {
        "n_items": len(tr), "n_1to1_pairs": len(sims),
        "sim_median": round(sorted(sims)[len(sims) // 2], 4) if sims else None,
        "dist": {f"{lo:.2f}-{hi:.2f}": sum(1 for x in sims if lo <= x < hi) for lo, hi in bins},
    }
    n95 = out["train"]["dist"]["0.95-1.01"]
    print(f"[학습] 1:1쌍 {len(sims)}  유사도 중앙값 {out['train']['sim_median']}  "
          f"0.95+ 쌍 {n95} ({n95/len(sims):.1%})  분포 {out['train']['dist']}")

    # ── (d) 근사 중복 누수 (shingle 역색인 + difflib) ─────────────────────
    tr_codes = [code_of(r["prompt"]) for r in tr]
    inv: dict[int, list[int]] = defaultdict(list)
    for i, c in enumerate(tr_codes):
        for sh in shingles(c):
            inv[sh].append(i)
    for split, name in EVAL:
        _, da = load(split)
        hits, checked = 0, 0
        examples = []
        for d in da:
            c = code_of(d["prompt"])
            cand = Counter()
            for sh in shingles(c):
                for i in inv.get(sh, ()):
                    cand[i] += 1
            best = 0.0
            for i, _ in cand.most_common(20):     # 공유 shingle 많은 순 상위 20개만
                checked += 1
                r = difflib.SequenceMatcher(None, c, tr_codes[i]).ratio()
                if r > best:
                    best = r
                if best >= LEAK_SIM:
                    break
            if best >= LEAK_SIM:
                hits += 1
                if len(examples) < 5:
                    examples.append({"eval_meta": d["meta"].get("pair_id") or d["meta"].get("cve_id"),
                                     "sim": round(best, 4)})
        out["leakage"][name] = {
            "n_eval": len(da), "n_near_dup_ge_0.95": hits,
            "ratio": round(hits / len(da), 4), "difflib_calls": checked,
            "examples": examples,
        }
        print(f"[누수 {name:10s}] {hits}/{len(da)} = {hits/len(da):.2%} (유사도 ≥ {LEAK_SIM})")

    out["leakage_method_limits"] = (
        "줄 3-shingle 역색인으로 후보를 좁힌 뒤 상위 20개만 difflib 로 확인했다. "
        "shingle 을 하나도 공유하지 않는 근사 중복과, 후보 21위 이하의 중복은 놓친다. "
        "따라서 이 수치는 **하한**이다.")

    p = ROOT / "out" / "phase0_materials.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"→ {p}")
    print(f"→ {ROOT / 'out' / 'phase0_sim95_pairs.jsonl'} ({len(rows_out)}행)")


if __name__ == "__main__":
    main()
