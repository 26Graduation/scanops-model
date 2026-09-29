"""Phase 2 — Joern precision 게이트 벤치 드라이버 (append·재개 가능)

입력 (읽기 전용, R2 준수):
  rebuild/data/cleanvul_v2_{tune,report}.jsonl      원본 코드 (prompt 안 코드블록)
  rebuild/out/ablation_raw_cleanvul_v2_{tune,report}.jsonl
                                                    case_id·label·lang·llm_score(캐시)
출력 (새 파일만):
  rebuild/out/joern_raw_cleanvul_v2_{tune,sample,report}.jsonl

사용:
  python joern/bench_joern.py tune
  python joern/bench_joern.py sample     # 층화 240건 (언어별 80 = vuln40/safe40, seed 42)
  python joern/bench_joern.py report     # 전건 1,878건

재개: 이미 기록된 case_id 는 건너뛴다. 언어별로 순차 실행하고 청크마다 flush 한다.
"""
from __future__ import annotations

import json
import os
import random
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from joern.handler_joern import analyze_batch  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "rebuild" / "data"
OUT = ROOT / "rebuild" / "out"

SUPPORTED = {"Java", "Python", "JavaScript"}
SEED = 42
STRATIFIED_PER_LANG_PER_LABEL = 40

_CODE_RE = re.compile(r"```[A-Za-z+#. /]*\n(.*?)```", re.S)


def extract_code(prompt: str) -> str:
    m = _CODE_RE.search(prompt)
    return m.group(1) if m else ""


def load_cases(split: str) -> list[dict]:
    """case_id → {case_id, lang, label, code, llm_score} (graph 지원 언어만)."""
    raw_path = OUT / f"ablation_raw_cleanvul_v2_{split}.jsonl"
    raw = {json.loads(l)["case_id"]: json.loads(l) for l in raw_path.open()}
    cases = []
    for line in (DATA / f"cleanvul_v2_{split}.jsonl").open():
        r = json.loads(line)
        meta = r["meta"]
        cid = f"{meta['pair_id']}|{meta['label']}"
        if meta["language"] not in SUPPORTED:
            continue
        a = raw.get(cid)
        if a is None:
            continue
        cases.append({
            "case_id": cid, "lang": meta["language"], "label": meta["label"],
            "code": extract_code(r["prompt"]),
            "llm_score": a.get("llm_score"),
            "graph_verdict": a.get("graph_verdict"),
        })
    return cases


def stratified_sample(cases: list[dict], n_per: int = STRATIFIED_PER_LANG_PER_LABEL) -> list[dict]:
    rng = random.Random(SEED)
    picked: list[dict] = []
    notes: list[str] = []
    for lang in sorted(SUPPORTED):
        for label in ("vuln", "safe"):
            pool = [c for c in cases if c["lang"] == lang and c["label"] == label]
            pool.sort(key=lambda c: c["case_id"])
            if len(pool) < n_per:
                notes.append(f"{lang}/{label}: {len(pool)} < {n_per} → 전량 사용")
                picked.extend(pool)
            else:
                picked.extend(rng.sample(pool, n_per))
    if notes:
        print("[sample] " + "; ".join(notes), flush=True)
    return picked


def main() -> int:
    split_arg = sys.argv[1] if len(sys.argv) > 1 else "sample"
    src_split = "tune" if split_arg == "tune" else "report"
    cases = load_cases(src_split)
    if split_arg == "sample":
        cases = stratified_sample(cases)

    out_path = OUT / f"joern_raw_cleanvul_v2_{split_arg}.jsonl"
    done: set[str] = set()
    if out_path.exists():
        for l in out_path.open():
            try:
                done.add(json.loads(l)["case_id"])
            except Exception:  # noqa: BLE001
                pass
    todo = [c for c in cases if c["case_id"] not in done]
    print(f"[bench] split={split_arg} total={len(cases)} done={len(done)} todo={len(todo)}", flush=True)

    deadline = time.time() + float(os.getenv("JOERN_BENCH_BUDGET_SEC", "9000"))  # 2.5h 상한
    chunk = int(os.getenv("JOERN_CHUNK", "25"))

    with out_path.open("a") as fh:
        for lang in sorted({c["lang"] for c in todo}):
            group = [c for c in todo if c["lang"] == lang]
            for i in range(0, len(group), chunk):
                if time.time() > deadline:
                    print("[bench] BUDGET_EXHAUSTED — 부분 표본으로 종료", flush=True)
                    return 2
                batch = group[i:i + chunk]
                job = f"bench_{split_arg}_{lang}_{i}_{int(time.time())}"
                try:
                    r = analyze_batch(job, lang,
                                      [{"path": c["case_id"], "content": c["code"]} for c in batch],
                                      chunk_size=chunk)
                except Exception as e:  # noqa: BLE001
                    print(f"[bench] CHUNK_FAIL {lang} {i}: {e}", flush=True)
                    continue
                rss = r.get("rss_curve", [])
                for c in batch:
                    v = r["results"].get(c["case_id"], {})
                    fh.write(json.dumps({
                        "case_id": c["case_id"], "lang": c["lang"], "label": c["label"],
                        "joern_verdict": v.get("verdict", "unknown"),
                        "categories": v.get("categories", []),
                        "unknown_reason": v.get("unknown_reason"),
                        "wrap_level": v.get("wrap_level"),
                        "elapsed": v.get("elapsed", 0.0),
                        "rss": (rss[-1]["peak_rss_mb"] if rss else None),
                        "llm_score": c["llm_score"],
                        "graph_verdict": c["graph_verdict"],
                    }, ensure_ascii=False) + "\n")
                fh.flush()
                print(f"[bench] {lang} {i}+{len(batch)} rss={rss[-1] if rss else None}", flush=True)
    print(f"[bench] DONE → {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
