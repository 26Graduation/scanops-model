"""
쌍 판별력 분해 — 내부/외부 AUC 격차가 "도메인"인지 "과제"인지 가른다
=====================================================================
오늘 §3-4 는 벤치를 두 층으로 갈랐다(함수 단위 0.87~0.91 vs 커밋 diff 쌍 0.56~0.62).
그 축의 정체를 확인한다: **평가셋이 쌍(같은 커밋의 취약본·패치본)으로 구성돼 있는가.**

재는 것:
  1. 각 split 의 **쌍 구성** — 완전쌍(같은 pair_id 에 vuln·safe 둘 다) 개수
  2. **쌍 내 순위 정확도** = P(score[vuln] > score[safe]) — 우연 수준 0.5
  3. **동점률** = 두 판본에 **완전히 같은 점수**를 준 비율 (= 구분 자체를 못 한 쌍)
  4. 학습셋이 이미 쌍으로 돼 있는지 — "쌍 데이터를 더 넣자"는 레버가 성립하는지 검정

비용 $0 — 기존 logprob 산출물과 데이터 파일만 읽는다.
실행: python3 rebuild/pair_discrimination.py [tag]
출력: out/pair_discrimination_{tag}.json
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from sweep_threshold import auc  # noqa: E402

TAG = sys.argv[1] if len(sys.argv) > 1 else "v1"
EVAL = ["test", "cleanvul_v2_report", "primevul_report", "cvefixes157", "cybernative154"]
TRAIN = ["train_v3", "val_v3"]


def load_scores(split: str) -> list[dict] | None:
    p = ROOT / "out" / f"{TAG}_logprob_{split}.jsonl"
    return [json.loads(l) for l in p.open()] if p.exists() else None


def load_data(split: str) -> list[dict] | None:
    p = ROOT / "data" / f"{split}.jsonl"
    return [json.loads(l) for l in p.open()] if p.exists() else None


def pair_key(meta: dict) -> str | None:
    """쌍 식별자. `pair_id` 가 있으면 그것, 없으면 `cve_id` 로 되돌린다.

    **중요:** 내부 test(`data/test.jsonl`)는 구버전 빌더로 만들어져 `pair_id` 필드가 없다.
    그러나 같은 CVE 의 취약본·패치본이 **둘 다 들어 있다**(641 CVE 중 496개).
    `pair_id` 만 보면 "쌍이 아니다"라고 잘못 읽게 된다 — 실제로 한 번 그렇게 읽었다(D-10 정정).
    """
    return meta.get("pair_id") or meta.get("cve_id") or None


def pair_stats(rows: list[dict]) -> dict:
    """정확히 1:1(취약 1건·안전 1건)인 쌍만 센다. 1:N 은 쌍 비교가 성립하지 않는다."""
    g = defaultdict(list)
    for r in rows:
        pid = pair_key(r["meta"])
        if pid is None:
            continue
        g[pid].append(r["meta"]["label"])
    full = sum(1 for v in g.values() if sorted(v) == ["safe", "vuln"])
    return {"n_items": len(rows), "n_pair_keys": len(g), "n_exact_1to1_pairs": full,
            "pair_key_source": ("pair_id" if rows and rows[0]["meta"].get("pair_id")
                                else "cve_id (pair_id 필드 없음)"),
            "paired_item_ratio": round(full * 2 / len(rows), 4) if rows else 0.0}


def main() -> None:
    out: dict = {"tag": TAG, "eval": {}, "train": {}}

    for sp in EVAL:
        recs = load_scores(sp)
        if recs is None:
            out["eval"][sp] = {"status": "미실행 — logprob 파일 없음"}
            continue
        ps = pair_stats(recs)
        g = defaultdict(lambda: defaultdict(list))
        for r in recs:
            pid = pair_key(r["meta"])
            if pid is None:
                continue
            g[pid][r["meta"]["label"]].append(r["score"])
        full = [{"vuln": v["vuln"][0], "safe": v["safe"][0]} for v in g.values()
                if len(v.get("vuln", [])) == 1 and len(v.get("safe", [])) == 1]
        e = {"auc": auc(recs), **ps}
        if full:
            win = sum(1 for v in full if v["vuln"] > v["safe"])
            tie = sum(1 for v in full if v["vuln"] == v["safe"])
            e["within_pair_rank_acc"] = round(win / len(full), 4)   # 우연 = 0.5
            e["within_pair_tie_rate"] = round(tie / len(full), 4)   # 같은 점수 = 구분 불가
            e["n_pairs_scored"] = len(full)
        out["eval"][sp] = e
        print(f"[{sp:20s}] AUC={e['auc']}  1:1쌍={ps['n_exact_1to1_pairs']:5d}/{ps['n_items']:5d}"
              + (f"  쌍내순위={e['within_pair_rank_acc']}  동점률={e['within_pair_tie_rate']}"
                 if full else "  (쌍 구성 아님)"))

    for sp in TRAIN:
        rows = load_data(sp)
        if rows is None:
            continue
        ps = pair_stats(rows)
        ps["source_dist"] = dict(Counter(r["meta"].get("source") for r in rows))
        out["train"][sp] = ps
        print(f"[학습 {sp:15s}] 항목 {ps['n_items']:6d}  1:1쌍 {ps['n_exact_1to1_pairs']:5d} "
              f"(쌍 항목 비율 {ps['paired_item_ratio']:.1%})  {ps['source_dist']}")

    p = ROOT / "out" / f"pair_discrimination_{TAG}.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"→ {p}")


if __name__ == "__main__":
    main()
