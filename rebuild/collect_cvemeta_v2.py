"""ScanOps v2 — CVEfixes 원본에서 completion 생성에 필요한 메타만 뽑아 캐시한다.

왜 필요한가: `rebuild/data/v4_meta.jsonl` 은 슬림 파일이라 `cwe_name` / `cwe_description` /
`cve_description` 이 없다. 그런데 v1 `build_dataset.py` 의 completion 은
  VULNERABILITY: CWE-89 (<cwe_name>)
  REASON: <extract_reason(cve_description, cwe_description)>
로 만들어진다. v2 도 **v1과 같은 출처·같은 함수**로 만들어야 completion 스타일이 변수로
끼어들지 않는다 (§12 "한 번에 한 변수").

출력: rebuild/data/v2_cvemeta.jsonl
  {"cve_id", "hash", "cwe_id", "cwe_name", "cwe_description", "cve_description"}

실행: .venv/bin/python rebuild/collect_cvemeta_v2.py
"""
from __future__ import annotations

import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "data" / "v2_cvemeta.jsonl"

WANT = ["cve_id", "hash", "cwe_id", "cwe_name", "cwe_description", "cve_description"]


def main() -> None:
    from datasets import load_dataset

    # v4_meta 의 5개 언어 후보 (cve_id, hash) 만 대상으로 한다 — 전량을 저장할 이유가 없다.
    LANG_MAP = {"python", "javascript", "typescript", "java", "php", "c", "c++", "cpp"}
    targets: set[tuple[str, str]] = set()
    for line in (ROOT / "data" / "v4_meta.jsonl").open():
        r = json.loads(line)
        if (r.get("language") or "").strip().lower() in LANG_MAP:
            targets.add((r["cve_id"], r["hash"]))
    print(f"[meta] 대상 (cve_id,hash) 조합 {len(targets)}개", flush=True)

    ds = load_dataset("hitoshura25/cvefixes", split="train", streaming=True)
    try:
        # 큰 컬럼(diff_with_context/vulnerable_code/fixed_code)을 빼면 전송량이 크게 준다.
        ds = ds.select_columns(WANT)
        print("[meta] select_columns 적용됨 (경량 스캔)", flush=True)
    except Exception as e:
        print(f"[meta] select_columns 미지원 → 전체 컬럼 스캔: {str(e)[:120]}", flush=True)

    t0 = time.time()
    found: dict[tuple[str, str], dict] = {}
    scanned = 0
    with OUT.open("w") as f:
        for r in ds:
            scanned += 1
            k = (r.get("cve_id"), r.get("hash"))
            if k in targets and k not in found:
                rec = {w: r.get(w) for w in WANT}
                # cve_description 은 [{'lang':..,'value':..}] 형태 → 문자열화해 두고
                # 해석은 v1 extract_reason() 에 맡긴다 (그 함수가 이미 처리한다).
                rec["cve_description"] = str(rec["cve_description"])
                found[k] = rec
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f.flush()
            if scanned % 1000 == 0:
                el = time.time() - t0
                print(f"[meta] scanned={scanned} found={len(found)}/{len(targets)} "
                      f"({el:.0f}s)", flush=True)
            if len(found) == len(targets):
                break
    el = time.time() - t0
    print(f"[meta] DONE scanned={scanned} found={len(found)}/{len(targets)} "
          f"미발견={len(targets)-len(found)} {el:.0f}s -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
