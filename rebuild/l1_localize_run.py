"""L1 — v1 localization ablation, 별도 2차 호출 (GRAPH_RUN_SPEC.md §16-3).

R1(v1 4줄)이 이미 "vuln"이라고 판정한 파일에, 라인 번호만 묻는 별도 LLM 호출을 붙인다.
학습·평가·서빙 4줄 템플릿(`build_dataset.py` / `bench_common.py` / `scripts/api_rebuild.py`)은
읽지도 고치지도 않는다. `PROMPT_TMPL_V2`(붕괴한 v2/v3)도 쓰지 않는다 — 아래 프롬프트가 유일한
정의처다.

모델: 베이스 Qwen3.5-9B, LoRA 어댑터 없음, 로컬 llama-server (§16-2, 사용자 확정).
입력: v1이 vuln으로 찍은 파일 전체(청크 아님) + v1의 기존 CWE/REASON을 사실로 제공.

실행: python rebuild/l1_localize_run.py juice-shop <repo_dir>
출력: rebuild/out/l1_localize_juice-shop.jsonl (재개 가능)
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
OUT = ROOT / "out"
sys.path.insert(0, str(ROOT))

from prompt_v2 import format_source_with_line_numbers  # noqa: E402 — 순수 포매터만 재사용
from repo_bench_scan import scan_files, SCOPE, CHATML_TMPL  # noqa: E402 — 스캔 범위·chat wrap 재사용

LLAMA = "http://127.0.0.1:8080"
MAX_CHARS = 45_000  # §16-3: 관측 최대 40,368자. 이보다 크면 컨텍스트 초과로 보고 skip.

# §16-3: v1 4줄(PROMPT_TMPL, FROZEN)·v2 5줄(PROMPT_TMPL_V2, 붕괴)와 별개인 새 프롬프트.
# L1은 재탐지가 아니라 국소화만 한다 — v1의 CWE/REASON을 사실로 제공한다.
L1_PROMPT_TMPL = """A static analysis pass already determined that the following {language} file \
contains a security vulnerability:

  CWE: {cwe}
  Reason given: {reason}

Here is the file with 1-based line numbers prepended to each line:

```{language}
{numbered_code}
```

Which single line number does this vulnerability correspond to? Respond in exactly this format \
and nothing else:
LINE: <line number>"""


def parse_line(raw: str) -> int | None:
    text = re.sub(r"<think>.*?</think>", "", raw, flags=re.S)
    for line in text.splitlines():
        s = line.strip()
        if s.upper().startswith("LINE:"):
            m = re.search(r"\d+", s.split(":", 1)[1])
            if m:
                return int(m.group(0))
    return None


def main(repo: str, repo_dir: Path) -> None:
    import requests
    from concurrent.futures import ThreadPoolExecutor

    lang = SCOPE[repo]["lang"]
    s1_path = OUT / f"repo_bench_{repo}_s1.jsonl"
    s1_rows = [json.loads(l) for l in s1_path.open()]
    vuln_rows = [r for r in s1_rows if r["label"] == "vuln"]
    print(f"v1 vuln 파일 {len(vuln_rows)} / {len(s1_rows)}")

    files_by_rel = {rel: code for rel, code in scan_files(repo, repo_dir)}

    out_path = OUT / f"l1_localize_{repo}.jsonl"
    done = set()
    if out_path.exists():
        done = {json.loads(l)["file"] for l in out_path.open()}
        print(f"재개: {len(done)}건 완료")

    def work(row):
        rel = row["file"]
        code = files_by_rel.get(rel)
        if code is None:
            return {"file": rel, "skip_reason": "file_not_found_in_scan"}
        if len(code) > MAX_CHARS:
            return {"file": rel, "skip_reason": "context_overflow", "chars": len(code)}
        numbered = format_source_with_line_numbers(code)
        prompt = L1_PROMPT_TMPL.format(
            language=lang, cwe=row.get("cwe") or "(unspecified)",
            reason=(row.get("raws") or [""])[0][:400], numbered_code=numbered)
        t0 = time.time()
        r = requests.post(f"{LLAMA}/completion", json={
            "prompt": CHATML_TMPL.format(p=prompt),
            "n_predict": 300, "temperature": 0.0,
            "stop": ["<|im_end|>"]}, timeout=900)
        r.raise_for_status()
        raw = r.json().get("content", "")
        return {
            "file": rel, "v1_cwe": row.get("cwe"), "v1_severity": row.get("severity"),
            "chars": len(code), "raw": raw[:800], "l1_line": parse_line(raw),
            "elapsed": round(time.time() - t0, 2),
        }

    todo = [r for r in vuln_rows if r["file"] not in done]
    t_all = time.time()
    with out_path.open("a") as f, ThreadPoolExecutor(max_workers=1) as ex:
        for i, rec in enumerate(ex.map(work, todo), 1):
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            if i % 10 == 0 or i == len(todo):
                print(f"  {i}/{len(todo)}  {time.time() - t_all:.0f}s 경과", flush=True)
    print(f"L1 완료: {out_path}  총 {time.time() - t_all:.0f}s")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "juice-shop",
         Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/private/tmp/scanops_repobench/juice-shop"))
