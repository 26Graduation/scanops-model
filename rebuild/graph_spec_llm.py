"""GRAPH-SPEC §5-2 — LLM taint 스펙 생성 (배치 호출).

후보를 **1건씩 호출하지 않는다**. 후보는 이미 호출 이름 단위로 dedupe 되어 있고
(파일 257개 → 후보 986개), 여기서 다시 BATCH 개씩 묶어 한 번에 라벨링한다.
호출 수 = ceil(후보수 / BATCH) 이고 사양 §3 상한 300회 안에 들어가야 한다.
들어가지 않으면 BATCH 를 키운다(아래 _plan 이 자동으로 올린다).

반과적합 장치 (사양 §9):
  - 프롬프트에서 **파일 경로·라인번호를 제거**한다. methodFullName 의
    `<file>::program:` 접두는 `<local>::` 로 치환한다.
  - 생성된 패턴에 소스 파일 경로(.ts/.js/...)나 `::program` 이 남아 있으면 **기계적으로 버린다**.
    버린 목록은 결과에 남긴다.

실행:
  python rebuild/graph_spec_llm.py juice-shop
출력:
  rebuild/out/graph_spec_raw_{repo}.jsonl   배치별 LLM 원본 응답 (checkpoint, append)
  rebuild/out/graph_spec_llm_{repo}.json    파싱·필터링된 스펙 + 메타데이터
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
OUT = ROOT / "out"

KST = timezone(timedelta(hours=9))
# 사양 §3 은 1라운드(juice-shop) 마감이었다. 기본값은 그대로 두어 그 라운드를 그대로 재현하면
# 여전히 마감 초과로 막힌다 — 다른 상수(CALL_CAP 등)처럼 env로 새 마감을 줄 수 있게만 한다
# (PLAN.md 1단계, 외부 레포용 신규 실행이라 §3 재현성과 무관).
DEADLINE = datetime.fromisoformat(os.getenv("GSPEC_DEADLINE_ISO", "2026-08-18T23:00:00+09:00"))
CALL_CAP = int(os.getenv("GSPEC_CALL_CAP", "300"))          # 사양 §3 스펙 생성 상한
BATCH = int(os.getenv("GSPEC_BATCH", "55"))
WORKERS = int(os.getenv("GSPEC_WORKERS", "6"))
MODEL = os.getenv("GSPEC_MODEL", "claude-opus-5")

# 허용 카테고리 — taint_v4.sc / multi_graph.py 와 같은 축을 쓴다
CATS = {
    "sqli": "CWE-89", "cmdi": "CWE-78", "xss": "CWE-79", "pathtraver": "CWE-22",
    "ssrf": "CWE-918", "deser": "CWE-502", "codei": "CWE-94", "redirect": "CWE-601",
    "nosqli": "CWE-943", "logforge": "CWE-117", "sensitive": "CWE-200",
    "accesscontrol": "CWE-284", "weakcrypto": "CWE-327", "proto": "CWE-1321",
}

SYSTEM = """You are a static-analysis expert writing taint-tracking specifications for the Joern code property graph engine.

You will be given a batch of API call names extracted from ONE repository, together with their resolved method-full-names and short usage snippets. For each API you decide what role it plays in taint analysis and emit a machine-readable rule.

HARD RULES — a violation makes the whole answer unusable:
1. Rules must describe GENERAL framework / library / language API behaviour. Never write a rule that keys on a source-file path, a project-specific file name, a line number, or a one-off local identifier. If an API is only meaningful because of where it happens to appear in this repository, label it "none".
2. Match `name` against the bare call name; match `full` against the method-full-name (library-qualified). Use `full` when the receiver/library matters (ORM query builders, chained calls, package-scoped constructors) — this is required for ORM and chained APIs.
3. Regex is Java syntax. Anchor name patterns (`^...$`) unless you deliberately want a family.
4. Be precise, not maximal. A sink that fires on every `get`/`send`/`write` destroys precision. Prefer `full` patterns that pin the library.
5. Only emit `propagation` for EXTERNAL library APIs whose taint behaviour Joern cannot see inside (argument -> return value, argument -> receiver). Index 0 = receiver/this, 1..n = positional arguments, "return" = return value.

Output ONE JSON array, no prose, no markdown fence. One object per input API, in the same order, each:
{"id": <int, echo the input id>,
 "role": "sink" | "source" | "sanitizer" | "none",
 "cat": "<category key, sink only>",
 "cwe": "CWE-nnn (sink only)",
 "match": "name" | "full",
 "pattern": "<Java regex>",
 "applies_to": ["<cat>", ...],           // sanitizer only; ["*"] means all categories
 "propagation": [{"from": <int|\"return\">, "to": <int|\"return\">}],   // optional
 "confidence": "high" | "med" | "low",
 "why": "<max 15 words>"}

Category keys and their CWE (use exactly these):
""" + "\n".join(f"  {k} = {v}" for k, v in CATS.items()) + """

role meanings:
  sink      — reaching this call with attacker-controlled data is the vulnerability
  source    — this call returns attacker-controlled data (request input, env, argv, stdin, file/DB reads of user data)
  sanitizer — this call neutralises tainted data for the categories in applies_to
  none      — irrelevant to taint analysis (the correct answer for most APIs)
"""

USER_TMPL = """Repository language: {lang}
Batch {bi}/{bn}. Label every API below.

{items}

Return the JSON array now."""

PATH_RE = re.compile(r"[A-Za-z0-9_./\-]+\.(ts|tsx|js|jsx|mjs|cjs|py|java|scala|go|rb|php)\b")
PROGRAM_RE = re.compile(r"::program")
LINE_RE = re.compile(r"(?:^|[^\w]):\d{1,5}\b")


def _load_env() -> None:
    for line in (REPO / ".env").read_text().splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


def norm_full(s: str) -> str:
    """methodFullName 에서 레포 파일 경로를 지운다 (반과적합, 사양 §9)."""
    s = re.sub(r"[A-Za-z0-9_./\-]+\.(ts|tsx|js|jsx|mjs|cjs)::program", "<local>::program", s)
    return s


def strip_locs(code: str) -> str:
    """스니펫에서 경로형 문자열과 줄번호를 지운다."""
    code = PATH_RE.sub("<path>", code)
    return code[:160]


def build_items(cand: dict) -> list[dict]:
    items = []
    for c in cand["calls"]:
        items.append({
            "kind": "call",
            "name": c["name"],
            "fulls": list(dict.fromkeys(norm_full(f["full"]) for f in c["fulls"]))[:3],
            "n": c["n"],
            "snippets": [strip_locs(x) for x in c["codes"][:2]],
        })
    # 파라미터: 위치 파라미터(p0/p1/param1_0…)는 이름에 정보가 없어 제외하고
    # **이름 있는 파라미터만** 이름 단위로 dedupe 한다.
    pos = re.compile(r"^(p\d+|param\d+(_\d+)?|arg\d+|_+)$")
    byname: dict[str, int] = {}
    for p in cand["params"]:
        if pos.match(p["param"]):
            continue
        byname[p["param"]] = byname.get(p["param"], 0) + p["n"]
    for nm, n in sorted(byname.items(), key=lambda kv: -kv[1]):
        items.append({"kind": "param", "name": nm, "fulls": [], "n": n, "snippets": []})
    for i, it in enumerate(items):
        it["id"] = i
    return items


def fmt_item(it: dict) -> str:
    if it["kind"] == "param":
        return (f'{{"id":{it["id"]},"kind":"function_parameter","name":"{it["name"]}",'
                f'"occurrences":{it["n"]}}}')
    return json.dumps({"id": it["id"], "kind": "call", "name": it["name"],
                       "full_names": it["fulls"], "occurrences": it["n"],
                       "snippets": it["snippets"]}, ensure_ascii=False)


def _plan(n_items: int) -> int:
    """호출 상한 안에 들어가도록 배치 크기를 키운다 (사양 §5)."""
    b = BATCH
    while (n_items + b - 1) // b > CALL_CAP:
        b *= 2
    return b


def main(repo: str) -> None:
    _load_env()
    import anthropic

    cand = json.loads((OUT / f"graph_spec_candidates_{repo}.json").read_text())
    lang = {"JSSRC": "TypeScript/JavaScript"}.get(cand["lang"], cand["lang"])
    items = build_items(cand)
    b = _plan(len(items))
    batches = [items[i:i + b] for i in range(0, len(items), b)]
    n_calls_planned = len(batches)
    print(f"[spec] 후보 {len(items)}건 (call {sum(1 for x in items if x['kind']=='call')}, "
          f"param {sum(1 for x in items if x['kind']=='param')}) "
          f"→ 배치 {b}개씩 = LLM 호출 {n_calls_planned}회 (상한 {CALL_CAP})", flush=True)
    if n_calls_planned > CALL_CAP:
        raise SystemExit("배치 계획이 상한을 넘었다 — 중단")

    raw_path = OUT / f"graph_spec_raw_{repo}.jsonl"
    done: set[int] = set()
    if raw_path.exists():
        for line in raw_path.open():
            try:
                done.add(json.loads(line)["batch"])
            except Exception:
                pass
        print(f"[spec] checkpoint 재개: 배치 {len(done)}개 완료됨")

    client = anthropic.Anthropic()
    lock = threading.Lock()
    state = {"calls": 0, "in_tok": 0, "out_tok": 0, "skipped_deadline": [], "errors": []}
    t0 = time.time()

    def work(bi: int) -> None:
        if bi in done:
            return
        if datetime.now(KST) >= DEADLINE:
            with lock:
                state["skipped_deadline"].append(bi)
            return
        with lock:
            if state["calls"] >= CALL_CAP:
                state["skipped_deadline"].append(bi)
                return
            state["calls"] += 1
        body = "\n".join(fmt_item(x) for x in batches[bi])
        user = USER_TMPL.format(lang=lang, bi=bi + 1, bn=len(batches), items=body)
        try:
            msg = client.messages.create(
                model=MODEL, max_tokens=16000, system=SYSTEM,
                thinking={"type": "disabled"},
                messages=[{"role": "user", "content": user}])
            text = "".join(bl.text for bl in msg.content if bl.type == "text")
            rec = {"batch": bi, "n_items": len(batches[bi]),
                   "ids": [x["id"] for x in batches[bi]], "model": MODEL, "raw": text}
            with lock:
                state["in_tok"] += msg.usage.input_tokens
                state["out_tok"] += msg.usage.output_tokens
                with raw_path.open("a") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                print(f"  batch {bi+1}/{len(batches)} ok ({len(text)}c)", flush=True)
        except Exception as e:
            with lock:
                state["errors"].append({"batch": bi, "error": str(e)[:300]})
                print(f"  batch {bi+1} ERROR {str(e)[:160]}", flush=True)

    only = int(os.getenv("GSPEC_ONLY", "0"))          # 스모크용: 앞 N개 배치만
    todo = range(len(batches)) if only <= 0 else range(min(only, len(batches)))
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        list(ex.map(work, todo))

    meta = {
        "repo": repo, "spec_model": MODEL, "external_api": True,
        "api_provider": "Anthropic Messages API",
        "n_candidates": len(items),
        "n_call_candidates": sum(1 for x in items if x["kind"] == "call"),
        "n_param_candidates": sum(1 for x in items if x["kind"] == "param"),
        "batch_size": b, "n_batches": len(batches),
        "llm_calls_made": state["calls"], "llm_call_cap": CALL_CAP,
        "input_tokens": state["in_tok"], "output_tokens": state["out_tok"],
        "wall_clock_seconds": round(time.time() - t0, 1),
        "batches_skipped_deadline_or_cap": state["skipped_deadline"],
        "errors": state["errors"],
        "raw_file": str(raw_path),
        "items_file": str(OUT / f"graph_spec_items_{repo}.json"),
    }
    (OUT / f"graph_spec_items_{repo}.json").write_text(
        json.dumps({"lang": cand["lang"], "items": items}, ensure_ascii=False, indent=2))
    (OUT / f"graph_spec_llm_{repo}_meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2))
    print(json.dumps(meta, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    main(sys.argv[1])
