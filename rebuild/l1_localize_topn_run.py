"""L1 top-N — GRAPH_RUN_SPEC.md §17-2. 파일당 1콜은 유지하되 후보를 최대 3개 받는다.

§16 의 top-1 버전(`l1_localize_run.py`, `L1_PROMPT_TMPL`)은 그대로 보존한다 — 이 파일이
top-N 버전이고, 결과 파일도 별도(`l1_localize_topn_{repo}.jsonl`)로 분리한다.

115개 v1-vuln 파일 전부에 균일 적용한다(§17-1 — 정답표를 보고 대상을 고르지 않는다).

실행: python rebuild/l1_localize_topn_run.py juice-shop <repo_dir>
출력: rebuild/out/l1_localize_topn_juice-shop.jsonl (재개 가능)
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

from prompt_v2 import format_source_with_line_numbers  # noqa: E402
from repo_bench_scan import scan_files, SCOPE, CHATML_TMPL  # noqa: E402

LLAMA = "http://127.0.0.1:8080"
MAX_CHARS = 45_000
N_CANDIDATES = 3  # §17-2

L1_TOPN_PROMPT_TMPL = """A static analysis pass already determined that the following {language} \
file contains a security vulnerability:

  CWE: {cwe}
  Reason given: {reason}

Here is the file with 1-based line numbers prepended to each line:

```{language}
{numbered_code}
```

List up to {n} candidate line numbers where this vulnerability could be, ordered from most to \
least likely. If you are only confident about fewer than {n}, use 0 for the remaining ones. \
Respond in exactly this format and nothing else:
LINE_1: <line number>
LINE_2: <line number or 0>
LINE_3: <line number or 0>"""


def parse_lines(raw: str) -> list[int]:
    text = re.sub(r"<think>.*?</think>", "", raw, flags=re.S)
    found: dict[int, int] = {}
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"LINE_(\d+):\s*(\d+)", s, re.I)
        if m:
            found[int(m.group(1))] = int(m.group(2))
    ordered = [found[k] for k in sorted(found)]
    return [n for n in ordered if n > 0]


def main(repo: str, repo_dir: Path) -> None:
    import requests
    from concurrent.futures import ThreadPoolExecutor

    lang = SCOPE[repo]["lang"]
    s1_path = OUT / f"repo_bench_{repo}_s1.jsonl"
    s1_rows = [json.loads(l) for l in s1_path.open()]
    vuln_rows = [r for r in s1_rows if r["label"] == "vuln"]
    print(f"v1 vuln 파일 {len(vuln_rows)} / {len(s1_rows)} (균일 적용, §17-1)")

    files_by_rel = {rel: code for rel, code in scan_files(repo, repo_dir)}

    out_path = OUT / f"l1_localize_topn_{repo}.jsonl"
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
        prompt = L1_TOPN_PROMPT_TMPL.format(
            language=lang, cwe=row.get("cwe") or "(unspecified)",
            reason=(row.get("raws") or [""])[0][:400], numbered_code=numbered, n=N_CANDIDATES)
        t0 = time.time()
        r = requests.post(f"{LLAMA}/completion", json={
            "prompt": CHATML_TMPL.format(p=prompt),
            "n_predict": 300, "temperature": 0.0,
            "stop": ["<|im_end|>"]}, timeout=900)
        r.raise_for_status()
        raw = r.json().get("content", "")
        return {
            "file": rel, "v1_cwe": row.get("cwe"), "v1_severity": row.get("severity"),
            "chars": len(code), "raw": raw[:800], "l1_lines": parse_lines(raw),
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
    print(f"L1 top-N 완료: {out_path}  총 {time.time() - t_all:.0f}s")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "juice-shop",
         Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/private/tmp/scanops_repobench/juice-shop"))
