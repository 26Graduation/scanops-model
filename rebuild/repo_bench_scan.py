"""Phase B — 레포 벤치 스캐너 (S1 / graph / Claude / 채점)

서브커맨드:
  inventory <repo> <dir>          스캔 대상 파일 목록·크기 통계
  s1        <repo> <dir>          S1 ScanOps-LLM (로컬 llama-server, 재개 가능)
  graph     <repo> <dir>          S2 의 그래프 성분 (code_graph 멀티파일 + multi_graph 단일파일)
  claude    <repo> <dir> [strong] C1/C2 (Anthropic Message Batches API)
  score     <repo>                B-3/B-4 채점

사양: rebuild/DUAL_ENGINE_RUN_SPEC.md §6 (측정 전 커밋 72d18e0)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
OUT = ROOT / "out"
DATA = ROOT / "data" / "repo_bench"
sys.path.insert(0, str(REPO_ROOT))

# ── 프롬프트: scripts/api_rebuild.py 와 **바이트 동일**해야 한다 (아래에서 검증) ──
PROMPT_TMPL = """Analyze the following {language} code for security vulnerabilities.

```{language}
{code}
```

Respond in exactly this format:
VULNERABILITY: <CWE-id (CWE name)> or NONE
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN> or NONE
CVSS: <score 0.0-10.0> or 0.0
REASON: <one-line explanation> or NONE"""
CHATML_TMPL = "<|im_start|>user\n{p}<|im_end|>\n<|im_start|>assistant\n"
MAX_CODE = 12_000


def _assert_prompt_parity() -> None:
    src = (REPO_ROOT / "scripts" / "api_rebuild.py").read_text()
    assert PROMPT_TMPL in src, "PROMPT_TMPL 이 api_rebuild.py 와 다르다 — 중단"
    # CHATML_TMPL 은 소스에 이스케이프된 리터럴로 적혀 있으므로 repr 로 비교한다
    assert repr(CHATML_TMPL)[1:-1] in src, "CHATML_TMPL 이 api_rebuild.py 와 다르다 — 중단"


def prompt_hash() -> str:
    return hashlib.sha256(PROMPT_TMPL.encode()).hexdigest()[:16]


# ── 스캔 범위 (사양 §6-d, 세 arm 동일) ────────────────────────────────────────
# juice-shop 엔트리는 v1(S1)·1~4라운드 arm 재현성 때문에 그대로 둔다 — 값을 바꾸지 않는다.
# PLAN.md 0단계: SCOPE에 없는 임의 레포는 아래 일반 규칙(GENERIC_EXT/GENERIC_EXCLUDE_DIRS)으로
# 스캔한다 — 매 레포마다 여기 항목을 손으로 추가하지 않아도 되게. 확장자·제외 디렉터리는
# `r4_cvefixes_pilot.py::EXT_JS`/`stage()`가 STEP7에서 이미 3레포에 실측으로 검증한 값 그대로다.
SCOPE = {
    "juice-shop": {
        "include": ["routes/**/*.ts", "lib/**/*.ts", "models/**/*.ts",
                    "server.ts", "app.ts", "frontend/src/app/**/*.ts"],
        "exclude_suffix": [".spec.ts", ".d.ts"],
        "lang": "TypeScript",
    },
}

GENERIC_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
# 2026-08-22 갱신: jquery-ui 실측(237개 JS 파일 중 129개=54%가 tests/external/demos)으로
# 발견 — 테스트·서드파티 번들·데모 코드는 "이 레포의 취약점"이 아니라 후보만 부풀린다.
# 특정 레포 이름이 아니라 일반적인 디렉터리 관례라서 벤치 과적합(CLAUDE.md 규칙4)이 아니다.
GENERIC_EXCLUDE_DIRS = {"node_modules", ".git", "dist", "build", "coverage",
                        "test", "tests", "spec", "specs", "external", "demo", "demos",
                        "vendor", "third_party", "__tests__"}
GENERIC_LANG = "JavaScript/TypeScript"


def _scan_files_generic(repo_dir: Path) -> list[tuple[str, str]]:
    """SCOPE에 없는 레포용 — 확장자 기반, 흔한 비-소스 디렉터리만 제외."""
    out = []
    for p in sorted(repo_dir.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in GENERIC_EXT:
            continue
        rel = p.relative_to(repo_dir)
        if any(part in GENERIC_EXCLUDE_DIRS for part in rel.parts):
            continue
        try:
            out.append((str(rel), p.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return out


def scan_files(repo: str, repo_dir: Path) -> list[tuple[str, str]]:
    """(상대경로, 내용) 목록. 정렬 고정."""
    if repo not in SCOPE:
        return _scan_files_generic(repo_dir)
    cfg = SCOPE[repo]
    seen: dict[str, Path] = {}
    for pat in cfg["include"]:
        for p in sorted(repo_dir.glob(pat)):
            if not p.is_file():
                continue
            rel = str(p.relative_to(repo_dir))
            if any(rel.endswith(s) for s in cfg["exclude_suffix"]):
                continue
            seen[rel] = p
    out = []
    for rel in sorted(seen):
        try:
            out.append((rel, seen[rel].read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return out


def chunks(code: str) -> list[str]:
    """12,000자 초과 파일 분할 — **줄 경계에서만** 자르고 겹치지 않는다.
    파일 판정 = 어느 한 청크라도 vuln 이면 vuln. S1·C1 에 같은 규칙을 쓴다."""
    if len(code) <= MAX_CODE:
        return [code]
    out, cur = [], []
    n = 0
    for line in code.splitlines(keepends=True):
        if n + len(line) > MAX_CODE and cur:
            out.append("".join(cur))
            cur, n = [], 0
        cur.append(line)
        n += len(line)
    if cur:
        out.append("".join(cur))
    return out


# ── 파서: rebuild/bench_common.py 의 것을 그대로 쓴다 ─────────────────────────
sys.path.insert(0, str(ROOT))
from bench_common import parse  # noqa: E402


# ═══════════════ inventory ═══════════════
def cmd_inventory(repo: str, repo_dir: Path) -> None:
    files = scan_files(repo, repo_dir)
    truth = [json.loads(l) for l in (DATA / f"{repo}_truth.jsonl").open()]
    in_scope = {f for f, _ in files}
    t_in = [t for t in truth if t["sink_file"] in in_scope]
    t_out = [t for t in truth if t["sink_file"] not in in_scope]
    stats = {
        "repo": repo, "n_files": len(files),
        "total_chars": sum(len(c) for _, c in files),
        "total_lines": sum(c.count("\n") + 1 for _, c in files),
        "files_over_12000c": sum(1 for _, c in files if len(c) > MAX_CODE),
        "total_chunks": sum(len(chunks(c)) for _, c in files),
        "truth_total": len(truth),
        "truth_in_scope": len(t_in),
        "truth_out_of_scope": len(t_out),
        "truth_out_of_scope_files": sorted({t["sink_file"] for t in t_out}),
        "truth_in_scope_cross_file": sum(1 for t in t_in if t["cross_file"]),
        "truth_files_in_scope": sorted({t["sink_file"] for t in t_in}),
        "prompt_sha256_16": prompt_hash(),
    }
    (OUT / f"repo_bench_{repo}_inventory.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2))
    print(json.dumps(stats, ensure_ascii=False, indent=2))


# ═══════════════ S1 — 로컬 llama-server ═══════════════
LLAMA = os.getenv("LLAMA_SERVER_URL", "http://127.0.0.1:8080")


def cmd_s1(repo: str, repo_dir: Path) -> None:
    """로컬 llama-server 로 파일 단위 판정. **재개 가능**(같은 명령을 다시 돌리면 이어서 한다).

    llama-server 는 `--parallel 2` 로 떠 있으므로 요청도 2개씩 겹쳐 보낸다.
    판정은 greedy(temperature 0)라 동시성이 결과를 바꾸지 않는다 — 순서만 달라진다.
    """
    import requests
    from concurrent.futures import ThreadPoolExecutor
    _assert_prompt_parity()
    lang = SCOPE[repo]["lang"]
    conc = int(os.getenv("RB_CONCURRENCY", "2"))
    out_path = OUT / f"repo_bench_{repo}_s1.jsonl"
    done = set()
    if out_path.exists():
        done = {json.loads(l)["file"] for l in out_path.open()}
        print(f"재개: {len(done)}건 완료 (동시성 {conc})")
    files = [(rel, code) for rel, code in scan_files(repo, repo_dir) if rel not in done]
    t_all = time.time()

    def work(item):
        rel, code = item
        t0 = time.time()
        parts = chunks(code)
        raws, labels = [], []
        for ch in parts:
            prompt = PROMPT_TMPL.format(language=lang, code=ch[:MAX_CODE])
            r = requests.post(f"{LLAMA}/completion", json={
                "prompt": CHATML_TMPL.format(p=prompt),
                "n_predict": 200, "temperature": 0.0,
                "stop": ["<|im_end|>"]}, timeout=900)
            r.raise_for_status()
            raw = r.json().get("content", "")
            raws.append(raw[:600])
            labels.append(parse(raw))
        vuln = [p for p in labels if p["label"] == "vuln"]
        return {
            "file": rel, "n_chunks": len(parts), "chars": len(code),
            "label": "vuln" if vuln else ("parse_fail" if all(
                p["label"] == "parse_fail" for p in labels) else "safe"),
            "cwe": vuln[0]["cwe"] if vuln else "",
            "severity": vuln[0]["severity"] if vuln else "",
            "raws": raws, "elapsed": round(time.time() - t0, 2),
        }

    with out_path.open("a") as f, ThreadPoolExecutor(max_workers=conc) as ex:
        for i, rec in enumerate(ex.map(work, files), 1):
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            if i % 10 == 0:
                print(f"  {i}/{len(files)}  {time.time() - t_all:.0f}s 경과", flush=True)
    print(f"S1 완료: {out_path}  총 {time.time() - t_all:.0f}s")


# ═══════════════ graph — S2 의 그래프 성분 ═══════════════
def cmd_graph(repo: str, repo_dir: Path) -> None:
    from scanops.core.code_graph import CodeFile, build_code_graph
    from scanops.core import multi_graph

    lang = SCOPE[repo]["lang"]
    files = scan_files(repo, repo_dir)
    t0 = time.time()

    # (1) 멀티파일 코드그래프 — 레포 전체를 한 번에 넣는다
    cg_files = [CodeFile(filename=rel, language=lang, content=code) for rel, code in files]
    graph = build_code_graph(cg_files)
    ev = [e.to_dict() for e in graph.evidence()]
    t_cg = time.time() - t0

    # (2) 단일파일 generic taint (multi_graph) — 파일마다 1회
    t1 = time.time()
    single = {}
    for rel, code in files:
        try:
            single[rel] = multi_graph.analyze(code[:MAX_CODE], lang)
        except Exception as e:  # noqa: BLE001
            single[rel] = {"verdict": "unknown", "category": "?", "reason": f"error {e}"}
    t_sg = time.time() - t1

    res = {
        "repo": repo, "n_files": len(files),
        "code_graph_seconds": round(t_cg, 2),
        "multi_graph_seconds": round(t_sg, 2),
        "code_graph_evidence": ev,
        "code_graph_vuln_files": sorted({e["filename"] for e in ev
                                         if e["verdict"] == "vuln"}),
        "multi_graph_verdicts": single,
        "multi_graph_vuln_files": sorted([r for r, v in single.items()
                                          if v["verdict"] == "vuln"]),
        "multi_graph_counts": {
            k: sum(1 for v in single.values() if v["verdict"] == k)
            for k in ("vuln", "safe", "unknown")},
    }
    p = OUT / f"repo_bench_{repo}_graph.json"
    p.write_text(json.dumps(res, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in res.items()
                      if k not in ("code_graph_evidence", "multi_graph_verdicts")},
                     ensure_ascii=False, indent=2))
    print(f"저장: {p}")


# ═══════════════ Claude — Message Batches ═══════════════
SYSTEM_PARITY = ("You are a security code analyzer. Analyze the given code and respond "
                 "ONLY in the exact 4-line format requested. Do not add explanation before or after.")
SYSTEM_STRONG = (
    "You are a senior application security engineer performing a code review. "
    "Think step by step about data flow: identify untrusted sources, follow them to "
    "dangerous sinks, and check whether any validation, encoding, or sanitization "
    "breaks the flow. Consider that the file may be safe. "
    "AFTER your analysis, end your reply with ONLY the exact 4-line format requested, "
    "with nothing after it."
)
CLAUDE_MODEL = "claude-opus-5"


def _load_env() -> None:
    for line in (REPO_ROOT / ".env").read_text().splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


def cmd_claude(repo: str, repo_dir: Path, strong: bool = False,
               limit: int | None = None) -> None:
    import anthropic
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request
    _assert_prompt_parity()
    _load_env()

    tag = f"{repo}_strong" if strong else f"{repo}_parity"
    lang = SCOPE[repo]["lang"]
    files = scan_files(repo, repo_dir)
    if limit:
        files = files[:limit]
    units = []                       # (file, chunk_idx, prompt)
    for rel, code in files:
        for j, ch in enumerate(chunks(code)):
            units.append((rel, j, PROMPT_TMPL.format(language=lang, code=ch[:MAX_CODE])))

    client = anthropic.Anthropic()
    id_file = OUT / f"repo_bench_claude_{tag}.id"
    if id_file.exists():
        batch_id = id_file.read_text().strip()
        print(f"[{tag}] 기존 배치 폴링: {batch_id}")
    else:
        print(f"[{tag}] {len(units)} 유닛 제출 (model={CLAUDE_MODEL}, strong={strong})")
        params = dict(model=CLAUDE_MODEL,
                      max_tokens=4000 if strong else 400,
                      system=SYSTEM_STRONG if strong else SYSTEM_PARITY)
        if not strong:
            # PARITY: 우리 모델과 같은 단일 패스. temperature 는 Claude 5 가 받지 않는다(사양 §2-c).
            params["thinking"] = {"type": "disabled"}
        reqs = [Request(custom_id=f"u{i}",
                        params=MessageCreateParamsNonStreaming(
                            **params, messages=[{"role": "user", "content": p}]))
                for i, (_, _, p) in enumerate(units)]
        batch = client.messages.batches.create(requests=reqs)
        batch_id = batch.id
        id_file.write_text(batch_id)
        print(f"batch id: {batch_id}")

    while True:
        b = client.messages.batches.retrieve(batch_id)
        if b.processing_status == "ended":
            break
        c = b.request_counts
        print(f"  처리 중… 성공 {c.succeeded} / 오류 {c.errored} / 진행 {c.processing}",
              flush=True)
        time.sleep(60)
    print(f"완료: 성공 {b.request_counts.succeeded} / 오류 {b.request_counts.errored}")

    raw_by: dict[int, str] = {}
    usage = {"input": 0, "output": 0}
    for result in client.messages.batches.results(batch_id):
        idx = int(result.custom_id[1:])
        if result.result.type == "succeeded":
            msg = result.result.message
            raw_by[idx] = "".join(bl.text for bl in msg.content if bl.type == "text")
            usage["input"] += msg.usage.input_tokens
            usage["output"] += msg.usage.output_tokens
        else:
            raw_by[idx] = f"ERROR: {result.result.type}"

    per_file: dict[str, list[dict]] = {}
    raws: dict[str, list[str]] = {}
    for i, (rel, _, _) in enumerate(units):
        raw = raw_by.get(i, "ERROR: missing")
        per_file.setdefault(rel, []).append(parse(raw))
        raws.setdefault(rel, []).append(raw.strip()[:600])

    recs = []
    for rel in sorted(per_file):
        labels = per_file[rel]
        vuln = [p for p in labels if p["label"] == "vuln"]
        recs.append({
            "file": rel, "n_chunks": len(labels),
            "label": "vuln" if vuln else ("parse_fail" if all(
                p["label"] == "parse_fail" for p in labels) else "safe"),
            "cwe": vuln[0]["cwe"] if vuln else "",
            "severity": vuln[0]["severity"] if vuln else "",
            "raws": raws[rel],
        })
    out_p = OUT / f"repo_bench_{repo}_{'c2_strong' if strong else 'c1_parity'}.jsonl"
    with out_p.open("w") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # 비용 (Message Batches = 정가의 50%; claude-opus-5 $5/$25 per MTok)
    cost = (usage["input"] / 1e6 * 5.0 + usage["output"] / 1e6 * 25.0) * 0.5
    meta = {"model": CLAUDE_MODEL, "batch_id": batch_id, "strong": strong,
            "n_units": len(units), "n_files": len(recs),
            "prompt_sha256_16": prompt_hash(),
            "usage": usage, "cost_usd_batch50pct": round(cost, 4),
            "called_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "unparsed": sum(1 for r in recs if r["label"] == "parse_fail")}
    (OUT / f"repo_bench_{repo}_{'c2_strong' if strong else 'c1_parity'}_meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2))
    print(json.dumps(meta, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    cmd = sys.argv[1]
    repo = sys.argv[2]
    OUT.mkdir(exist_ok=True)
    if cmd == "inventory":
        cmd_inventory(repo, Path(sys.argv[3]))
    elif cmd == "s1":
        cmd_s1(repo, Path(sys.argv[3]))
    elif cmd == "graph":
        cmd_graph(repo, Path(sys.argv[3]))
    elif cmd == "claude":
        cmd_claude(repo, Path(sys.argv[3]), strong=("strong" in sys.argv[4:]),
                   limit=int(os.getenv("RB_LIMIT", "0")) or None)
    else:
        raise SystemExit(f"unknown cmd {cmd}")
