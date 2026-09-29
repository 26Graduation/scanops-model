"""Phase 1 — Joern **v3(sanitizer-aware)** 배치 드라이버 (append·재개 가능)

어젯밤 드라이버(bench_joern.py)와의 차이:
  · path / sanitizer_hits / pair_id 를 **저장한다** (어젯밤엔 findings 를 버려 path 보유율 0%였다)
  · verdict 에 safe_sanitized 가 추가된다
  · vuln 인데 path 가 비면 verdict=unknown(reason=no_path) 로 낮추고 건수를 센다

입력 (읽기 전용, R2 준수):
  rebuild/data/cleanvul_v2_{tune,report}.jsonl
  rebuild/out/ablation_raw_cleanvul_v2_{tune,report}.jsonl
출력 (새 파일만, _v3 꼬리표):
  rebuild/out/joern_v4fix_raw_cleanvul_v2_{tune,sample,report}.jsonl

사용:
  python joern/bench_joern_v4.py tune
  python joern/bench_joern_v4.py sample    # 어젯밤과 동일한 층화 240건 (seed 42)
  python joern/bench_joern_v4.py report
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "rebuild" / "out"

# ── v3 쿼리 강제 ────────────────────────────────────────────────────────────
# handler_joern 은 **import 시점에** SCRIPT 상수를 환경변수에서 읽는다.
# bench_joern 도 handler_joern 을 import 하므로, 어떤 joern 모듈보다 **먼저**
# 환경변수를 세팅해야 한다. (실측 사고: 아래 import 뒤에 두었더니 v1 taint.sc 로 돌았다.)
_V3 = str(ROOT / "joern" / "queries" / "taint_v4.sc")
os.environ["JOERN_SCRIPT"] = _V3

from joern.bench_joern import load_cases, stratified_sample  # noqa: E402
from joern.handler_joern import SCRIPT as _ACTIVE_SCRIPT, analyze_batch  # noqa: E402
from joern.langmap import resolve  # noqa: E402
from joern.sanitizer_spec import write_san_file  # noqa: E402

if Path(_ACTIVE_SCRIPT).name != "taint_v4.sc":  # 조용한 오실행 방지
    raise SystemExit(f"[v4fix] FATAL: 활성 쿼리가 v3 가 아니다 → {_ACTIVE_SCRIPT}")


def _flatten_path(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """살아남은(sanitized=False) finding 들의 path 중 **가장 긴 것** 하나를 대표로 쓴다.

    Critic 입력은 흐름 하나여야 하고, 가장 긴 흐름이 sanitizer 판단에 필요한
    중간 노드를 가장 많이 담고 있기 때문이다.
    """
    live = [f for f in findings if not f.get("sanitized")]
    if not live:
        return [], []
    best = max(live, key=lambda f: len(f.get("path") or []))
    return (best.get("path") or []), (best.get("sanitizer_hits") or [])


def main() -> int:
    split_arg = sys.argv[1] if len(sys.argv) > 1 else "sample"
    src_split = "tune" if split_arg == "tune" else "report"
    cases = load_cases(src_split)
    if split_arg == "sample":
        cases = stratified_sample(cases)

    out_path = OUT / f"joern_v4fix_raw_cleanvul_v2_{split_arg}.jsonl"
    done: set[str] = set()
    if out_path.exists():
        for line in out_path.open():
            try:
                done.add(json.loads(line)["case_id"])
            except Exception:  # noqa: BLE001
                pass
    todo = [c for c in cases if c["case_id"] not in done]
    print(f"[v4fix] split={split_arg} total={len(cases)} done={len(done)} todo={len(todo)}", flush=True)

    deadline = time.time() + float(os.getenv("JOERN_BENCH_BUDGET_SEC", "9000"))
    chunk = int(os.getenv("JOERN_CHUNK", "25"))
    no_path = 0

    # 언어별 sanFile 을 미리 만들어 둔다 (핸들러가 환경변수로 읽는다)
    san_dir = Path(os.getenv("TMPDIR", "/tmp")) / "scanops_v4fix_san"
    san_dir.mkdir(parents=True, exist_ok=True)
    san_files: dict[str, Path] = {}
    for lang in sorted({c["lang"] for c in cases}):
        r = resolve(lang)
        if r is None:
            continue
        jl = r[1]
        if jl in san_files:
            continue
        p = san_dir / f"{jl}.txt"
        n = write_san_file(jl, p)
        san_files[jl] = p
        print(f"[v4fix] sanFile {jl}: {n} patterns → {p}", flush=True)

    with out_path.open("a") as fh:
        for lang in sorted({c["lang"] for c in todo}):
            group = [c for c in todo if c["lang"] == lang]
            r_lang = resolve(lang)
            if r_lang is not None:
                os.environ["JOERN_SANITIZER_FILE"] = str(san_files.get(r_lang[1], ""))
            for i in range(0, len(group), chunk):
                if time.time() > deadline:
                    print("[v4fix] BUDGET_EXHAUSTED — 부분 표본으로 종료", flush=True)
                    return 2
                batch = group[i:i + chunk]
                job = f"v4_{split_arg}_{lang}_{i}_{int(time.time())}"
                try:
                    res = analyze_batch(job, lang,
                                        [{"path": c["case_id"], "content": c["code"]} for c in batch],
                                        chunk_size=chunk)
                except Exception as e:  # noqa: BLE001
                    print(f"[v4fix] CHUNK_FAIL {lang} {i}: {e}", flush=True)
                    continue
                rss = res.get("rss_curve", [])
                for c in batch:
                    v = res["results"].get(c["case_id"], {})
                    verdict = v.get("verdict", "unknown")
                    reason = v.get("unknown_reason")
                    path, hits = _flatten_path(v.get("findings") or [])
                    # vuln 인데 path 가 비면 Critic 입력이 없다 → unknown 으로 낮춘다
                    if verdict == "vuln" and not path:
                        verdict, reason = "unknown", "no_path"
                        no_path += 1
                    if verdict == "safe_sanitized" and not hits:
                        hits = v.get("sanitizer_hits") or []
                    fh.write(json.dumps({
                        "case_id": c["case_id"],
                        "pair_id": c["case_id"].split("|")[0],
                        "lang": c["lang"], "label": c["label"],
                        "joern_verdict": verdict,
                        "categories": v.get("categories", []),
                        "sanitized_categories": v.get("sanitized_categories", []),
                        "sanitizer_hits": hits,
                        "path": path,
                        "unknown_reason": reason,
                        "wrap_level": v.get("wrap_level"),
                        "elapsed": v.get("elapsed", 0.0),
                        "rss": (rss[-1]["peak_rss_mb"] if rss else None),
                        "llm_score": c["llm_score"],
                        "graph_verdict": c["graph_verdict"],
                    }, ensure_ascii=False) + "\n")
                fh.flush()
                print(f"[v4fix] {lang} {i}+{len(batch)} no_path_so_far={no_path} "
                      f"rss={rss[-1]['peak_rss_mb'] if rss else None}", flush=True)
    print(f"[v4fix] DONE → {out_path}  no_path={no_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
