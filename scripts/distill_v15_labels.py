"""V15 앙상블 → V16 증류 라벨 생성 (로컬 Ollama, 재개 가능)
================================================================
목적: v16 후보(data/v16_candidates.jsonl)의 각 코드에 대해 V15 앙상블 구성요소
(v13·v14·그래프) 투표를 기록한다. build_dataset_v16 --stage build 가 이 votes 로
라벨 노이즈를 거른다(기본 규칙: GT=안전 ∧ v14=취약 → 제외).

왜 v14 가 교사인가: v14는 전 벤치 오탐률 5~16%의 고정밀 모델. v14가 "안전" 라벨
후보를 취약이라 하면 원 데이터셋 라벨이 틀렸을 가능성이 높다(PrimeVul도 라벨
노이즈 존재). 반대로 GT=취약은 무조건 유지하므로 v13/그래프 투표는 분석용 기록.

전제: 로컬 Ollama 에 qwen2.5-coder-security-v13-7b, -v14-7b 로드 가능(맥 RAM ~11GB).
비용: 케이스당 ~5-8초(두 모델 병렬). 3,600개 ≈ 5~8시간 → 밤에 돌려두면 됨.
      --safe-only(기본 on)면 안전 후보만 돌려 절반 이하로 단축.

실행: python scripts/distill_v15_labels.py            # 안전 후보만(권장, 필터에 충분)
      python scripts/distill_v15_labels.py --all      # 전체(분석용 votes 포함)
      중단해도 재실행하면 이어서 진행(append + hash 스킵).
산출: data/v16_distill.jsonl  ({hash, label, votes:{v13,v14,graph}})
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CANDIDATES = ROOT / "data" / "v16_candidates.jsonl"
OUT = ROOT / "data" / "v16_distill.jsonl"


def main(safe_only: bool, limit: int | None):
    from scanops.core.ensemble import _llm_analyze, V13_MODEL, V14_MODEL
    from scanops.core.multi_graph import analyze as graph_analyze
    from concurrent.futures import ThreadPoolExecutor

    if not CANDIDATES.exists():
        sys.exit(f"후보 파일 없음: {CANDIDATES} — 먼저 python -m ml.build_dataset_v16 --stage candidates")

    done: set[str] = set()
    if OUT.exists():
        for line in OUT.read_text().splitlines():
            if line.strip():
                done.add(json.loads(line)["hash"])
        print(f"기존 진행분 {len(done)}개 — 이어서 진행")

    rows = [json.loads(l) for l in CANDIDATES.read_text().splitlines() if l.strip()]
    todo = [r for r in rows
            if r["hash"] not in done and (not safe_only or r["label"] == "safe")]
    if limit:
        todo = todo[:limit]
    print(f"대상 {len(todo)}개 (safe_only={safe_only})")

    t0 = time.time()
    with open(OUT, "a", encoding="utf-8") as f:
        for i, r in enumerate(todo, 1):
            code, lang = r["code"], r["language"]
            with ThreadPoolExecutor(max_workers=2) as ex:
                f13 = ex.submit(_llm_analyze, code, lang, V13_MODEL)
                f14 = ex.submit(_llm_analyze, code, lang, V14_MODEL)
                a13, a14 = f13.result(), f14.result()
            try:
                g = graph_analyze(code, lang)
                gv = g["verdict"] == "vuln"
            except Exception:  # noqa: BLE001
                gv = False
            f.write(json.dumps({
                "hash": r["hash"], "label": r["label"], "src": r["src"],
                "votes": {"v13": a13["vulnerable"], "v14": a14["vulnerable"], "graph": gv},
            }, ensure_ascii=False) + "\n")
            f.flush()
            if i % 20 == 0:
                el = time.time() - t0
                print(f"  {i}/{len(todo)} | {el/60:.1f}분 경과 | "
                      f"잔여 예상 {(el/i)*(len(todo)-i)/60:.0f}분", flush=True)
    print(f"완료 → {OUT}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="취약 후보까지 전부 라벨링(분석용)")
    ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args()
    main(safe_only=not a.all, limit=a.limit)
