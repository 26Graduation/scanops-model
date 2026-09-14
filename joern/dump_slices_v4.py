"""전략 E 재료 — Critic 대상 98건에 대해 **모든 flow 의 path 합집합**을 덤프.

어제 파이프라인은 `live`(sanitizer 에 안 걸린 흐름)만 골라 Critic 에게 줬다.
그건 regex 가 "sanitizer 없다"고 판정한 흐름을 놓고 "있는가"를 묻는 **순환**이다(§8 D-3).
여기서는 필터 없이 전부 모아 (line 오름차순, 중복 제거) 하나의 슬라이스로 만든다.

출력: rebuild/out/slices_union_v4.jsonl
      {case_id, pair_id, lang, label, categories[], path[{line,code,role}], n_flows}
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["JOERN_SCRIPT"] = str(ROOT / "joern" / "queries" / "taint_v4.sc")

from joern.bench_joern import load_cases  # noqa: E402
from joern.handler_joern import analyze_batch  # noqa: E402
from joern.langmap import resolve  # noqa: E402
from joern.sanitizer_spec import write_san_file  # noqa: E402

OUT = ROOT / "rebuild" / "out"


def union_path(findings: list[dict]) -> tuple[list[dict], int]:
    """모든 finding 의 path 를 합친다 — **sanitized 여부로 거르지 않는다**."""
    seen: set[tuple] = set()
    steps: list[dict] = []
    for f in findings:
        for s in (f.get("path") or []):
            key = (s.get("line"), (s.get("code") or "").strip())
            if key in seen:
                continue
            seen.add(key)
            steps.append(s)
    steps.sort(key=lambda s: (s.get("line") if isinstance(s.get("line"), int) else 10**6))
    return steps, len(findings)


def main() -> int:
    # 대상: 어제 Critic 이 본 것과 같은 98건
    v3 = [json.loads(l) for l in (OUT / "joern_v3_raw_cleanvul_v2_tune.jsonl").open()]
    want = {r["case_id"] for r in v3 if r["joern_verdict"] == "vuln" and r.get("path")}
    cases = [c for c in load_cases("tune") if c["case_id"] in want]
    print(f"[dump] 대상 {len(cases)}건", flush=True)

    san_dir = Path(os.getenv("TMPDIR", "/tmp")) / "scanops_v4_san"
    san_dir.mkdir(parents=True, exist_ok=True)

    out_path = OUT / "slices_union_v4.jsonl"
    done = set()
    if out_path.exists():
        for line in out_path.open():
            try:
                done.add(json.loads(line)["case_id"])
            except Exception:  # noqa: BLE001
                pass

    with out_path.open("a") as fh:
        for lang in sorted({c["lang"] for c in cases}):
            group = [c for c in cases if c["lang"] == lang and c["case_id"] not in done]
            if not group:
                continue
            r = resolve(lang)
            if r is None:
                continue
            jl = r[1]
            p = san_dir / f"{jl}.txt"
            write_san_file(jl, p)
            os.environ["JOERN_SANITIZER_FILE"] = str(p)
            for i in range(0, len(group), 25):
                batch = group[i:i + 25]
                res = analyze_batch(f"dump_{lang}_{i}", lang,
                                    [{"path": c["case_id"], "content": c["code"]} for c in batch],
                                    chunk_size=25)
                for c in batch:
                    v = res["results"].get(c["case_id"], {})
                    steps, nf = union_path(v.get("findings") or [])
                    fh.write(json.dumps({
                        "case_id": c["case_id"], "pair_id": c["case_id"].split("|")[0],
                        "lang": c["lang"], "label": c["label"],
                        "categories": sorted({f.get("category") for f in (v.get("findings") or [])
                                              if f.get("category")}),
                        "path": steps, "n_flows": nf,
                        "verdict": v.get("verdict"),
                    }, ensure_ascii=False) + "\n")
                fh.flush()
                print(f"[dump] {lang} {i}+{len(batch)}", flush=True)
    print(f"[dump] DONE → {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
