"""
CTX-1 — 문맥 주입 프롬프트 빌더 (사양서 §3)
============================================
PrimeVul report split(288건 / 144쌍)에 대해 4개 arm의 프롬프트를 만든다.

  T0        현행 함수 단위 (primevul_report.jsonl 프롬프트를 **바이트 그대로** 복사)
  T1        함수 + 같은 파일의 문맥
  T1-shuf   함수 + **무작위 다른 케이스**의 문맥 (길이/형식 교란 통제)
  T1-nofunc 문맥만 (대상 함수 본문 제거)

문맥 수집 규칙:
  - 레포 클론 금지. GitHub API로 **해당 커밋 시점의 그 파일 1개만** 받는다.
  - 취약본은 fix 커밋의 **부모** 시점, 패치본은 fix 커밋 시점에서 각자 받는다.
    (PrimeVul의 commit_id는 fix 커밋이고, target=1 행이 그 부모 시점의 함수다)
  - 라벨 누출 금지: diff·커밋 메시지·CVE·CWE·날짜·브랜치명은 절대 넣지 않는다.
    우리가 넣는 것은 **파일 본문에서 잘라낸 코드뿐**이다.

문맥 구성(사양서 §3-3 우선순위):
  (1) 파일 상단 #include / import / 매크로 / 상수
  (2) 대상 함수가 참조하는 구조체·타입 정의 (같은 파일)
  (3) 같은 파일에서 대상 함수를 호출하는 지점 ±20줄
  (4) 대상 함수가 호출하는 같은 파일 내 함수 본문
  (5) 대상 함수 본문 (원문 그대로)

8,000 토큰 상한 초과 시 (4)→(3)→(2)→(1) 순으로 잘라낸다.
※ 사양서 문구는 "우선순위 역순"이지만, 문자 그대로면 (5) 대상 함수부터 버리게 되어
   실험이 성립하지 않는다. 대상 함수는 항상 보존하고 그 위 항목부터 버린다.
   이 해석은 CTX_RESULTS.md에 명시한다.

실행: python rebuild/build_ctx_prompts.py [split]
      split 기본값은 primevul_report. τ 선정용으로 primevul_tune도 만든다
      (사양서 §4-7: 임계값은 tune split에서만 고른다).
"""
from __future__ import annotations

import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
CACHE = DATA / "ctx_cache"
OUT = ROOT / "out"

MAX_CTX_TOKENS = 8_000          # 사양서 §3-4
CALLER_WINDOW = 20              # 호출부 ±20줄
SEED = 42

TOKEN = os.environ.get("GITHUB_TOKEN", "")
UA = {"User-Agent": "scanops-ctx1", "Accept": "application/vnd.github+json"}
if TOKEN:
    UA["Authorization"] = f"Bearer {TOKEN}"

# 프롬프트 꼬리(응답 포맷)는 T0와 **완전히 동일**해야 한다 — logprob 층이 여기에 걸려 있다.
TAIL = """Respond in exactly this format:
VULNERABILITY: <CWE-id (CWE name)> or NONE
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN> or NONE
CVSS: <score 0.0-10.0> or 0.0
REASON: <one-line explanation> or NONE"""


# ── GitHub: 커밋 메타 + 파일 1개 ─────────────────────────────────────────────
class RateLimited(Exception):
    pass


def _get(url: str, raw: bool = False) -> bytes:
    req = urllib.request.Request(url, headers=dict(UA, **({"Accept": "application/vnd.github.raw"} if raw else {})))
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                remaining = e.headers.get("x-ratelimit-remaining")
                if remaining == "0":
                    raise RateLimited(url) from e
                time.sleep(2 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            time.sleep(2 * (attempt + 1))
    raise urllib.error.URLError(f"retry exhausted: {url}")


def cached(key: str, fetch) -> bytes | None:
    """디스크 캐시. None은 '이 키는 실패했다'를 뜻하며 빈 파일로 캐시한다."""
    p = CACHE / key
    if p.exists():
        b = p.read_bytes()
        return None if b == b"" else b
    try:
        b = fetch()
    except RateLimited:
        raise
    except Exception:
        p.write_bytes(b"")
        return None
    p.write_bytes(b)
    return b


# PrimeVul의 project_url은 kernel.org/savannah 등 비-GitHub도 많다.
# 리눅스 커널 서브트리(net, bpf, ipsec, wireless-drivers, linux-2.6 …)는 머지된 커밋 SHA가
# torvalds/linux 미러에 그대로 있으므로 그쪽으로 폴백한다. (커밋 SHA가 없으면 어차피 실패 처리)
KERNEL_RE = re.compile(r"git\.kernel\.org/.*/(?:linux|net|bpf|ipsec|wireless[-\w]*|scsi|tip|kvm|[\w.-]+)")


def repo_of(project_url: str) -> str | None:
    u = (project_url or "").strip()
    m = re.search(r"github\.com/([^/]+)/([^/\s]+?)(?:\.git)?/?$", u)
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    if KERNEL_RE.search(u):
        return "torvalds/linux"
    m = re.search(r"gitlab\.com/([^/]+)/([^/\s]+?)(?:\.git)?/?$", u)
    if m:                       # gitlab 미러가 GitHub에도 있는 경우가 있어 한 번 시도한다
        return f"{m.group(1)}/{m.group(2)}"
    return None


CODE_EXT = {"c", "cc", "cpp", "cxx", "h", "hpp", "hh", "c++", "cp", "inc"}


def commit_meta(repo: str, sha: str) -> dict | None:
    key = f"commit_{repo.replace('/', '__')}_{sha}.json"
    b = cached(key, lambda: _get(f"https://api.github.com/repos/{repo}/commits/{sha}"))
    if b is None:
        return None
    d = json.loads(b)
    return {"parent": d["parents"][0]["sha"] if d.get("parents") else None,
            "files": [f["filename"] for f in d.get("files", [])]}


def file_at(repo: str, sha: str, path: str) -> str | None:
    key = f"blob_{repo.replace('/', '__')}_{sha}_{path.replace('/', '__')}"
    b = cached(key, lambda: _get(f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"))
    if b is None:
        return None
    try:
        return b.decode("utf-8", errors="replace")
    except Exception:
        return None


# ── 아주 얇은 C/C++ 구조 추출기 ──────────────────────────────────────────────
# 사양서 §9가 금지하는 것은 Joern/tree-sitter **엔진 구현**이며(=T2 범위),
# 여기서는 같은 파일 안에서 함수·타입 블록의 경계만 중괄호로 찾는다.
FUNC_RE = re.compile(
    r"^[A-Za-z_#~][^\n;{}=]{0,400}?\b(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*?\)"
    r"(?:\s*(?:const|noexcept|override|final|OVERRIDE|TF_[A-Z_]+))*\s*\{",
    re.M | re.S)
TYPE_RE = re.compile(
    r"^(?:typedef\s+)?(?:struct|union|enum|class)\s+(?P<name>[A-Za-z_]\w*)?\s*"
    r"(?::\s*[^{;]+?)?\s*\{", re.M)
# `typedef struct { ... } Foo;` 처럼 여는 쪽에 이름이 없는 정의는 닫는 쪽에서 이름을 읽는다.
ANON_NAME_RE = re.compile(r"^\s*\*?\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*[,;]")
IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "catch", "do", "else",
            "case", "defined", "static_cast", "reinterpret_cast", "const_cast", "dynamic_cast"}


def brace_span(text: str, open_idx: int) -> int:
    """text[open_idx] == '{' 에서 짝이 맞는 '}' 다음 위치. 문자열/주석은 대충 건너뛴다."""
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            i = text.find("\n", i)
            if i < 0:
                return n
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 1
        elif c in "\"'":
            q, i = c, i + 1
            while i < n and text[i] != q:
                i += 2 if text[i] == "\\" else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def find_blocks(text: str, regex) -> list[tuple[str, int, int]]:
    out = []
    for m in regex.finditer(text):
        name = m.groupdict().get("name") or ""
        if name in KEYWORDS:
            continue
        ob = text.find("{", m.end() - 1)
        if ob < 0:
            continue
        out.append((name, m.start(), brace_span(text, ob)))
    return out


def top_matter(text: str, limit_lines: int = 400, stop_line: int | None = None) -> str:
    """(1) 파일 상단 include/define/typedef 한 줄짜리/상수.

    stop_line(=파일 내 첫 함수 정의가 시작하는 줄)까지만 본다. 그 아래에서 긁으면
    함수 **내부**의 const 선언까지 딸려 와 '상단 문맥'이 아니게 된다.
    """
    keep, lines = [], text.splitlines()
    upto = len(lines) if stop_line is None else max(stop_line, 1)
    for ln in lines[:upto]:
        s = ln.strip()
        if s.startswith(("#include", "#define", "#pragma", "#undef", "#if", "#elif", "#else", "#endif")):
            keep.append(ln)
        elif re.match(r"^\s*(typedef|using)\b.*;\s*$", ln):
            keep.append(ln)
        elif re.match(r"^\s*(static\s+)?const\s+[\w:<>*&\s]+\w+\s*(=|\[).*;\s*$", ln):
            keep.append(ln)
        elif re.match(r"^\s*(namespace|extern\s+\"C\")\b.*$", ln):
            keep.append(ln)
        if len(keep) >= limit_lines:
            break
    return "\n".join(keep)


def locate_func(text: str, func: str, funcs: list[tuple[str, int, int]]) -> tuple[int, int] | None:
    """파일 안에서 대상 함수의 (start, end). 정확 일치 → 공백 정규화 일치 → 이름 일치."""
    idx = text.find(func)
    if idx >= 0:
        return idx, idx + len(func)
    norm = lambda s: re.sub(r"\s+", " ", s).strip()
    tgt = norm(func)
    for name, s, e in funcs:
        if norm(text[s:e]) == tgt:
            return s, e
    fname = func_name_of(func)
    if fname:
        cands = [(s, e) for name, s, e in funcs if name == fname]
        if len(cands) == 1:
            return cands[0]
        if cands:  # 동명이인 → 본문이 가장 비슷한 것
            return max(cands, key=lambda se: _sim(norm(text[se[0]:se[1]]), tgt))
    return None


def _sim(a: str, b: str) -> float:
    sa, sb = set(a.split()), set(b.split())
    return len(sa & sb) / max(1, len(sa | sb))


def func_name_of(func: str) -> str:
    m = FUNC_RE.search(func if func.rstrip().endswith("}") else func + "\n{")
    if m:
        return m.group("name")
    m = re.search(r"\b([A-Za-z_]\w*)\s*\(", func)
    return m.group(1) if m else ""


def build_context(text: str, func: str) -> tuple[dict[str, str], dict]:
    """(1)~(4) 섹션과 진단 정보를 만든다. 대상 함수 본문(5)은 호출부에서 따로 붙인다."""
    funcs = find_blocks(text, FUNC_RE)
    span = locate_func(text, func, funcs)
    info = {"located": span is not None, "n_funcs_in_file": len(funcs)}
    lines = text.splitlines()
    s_line = e_line = -1
    if span:
        s_line = text.count("\n", 0, span[0])
        e_line = text.count("\n", 0, span[1])
    fname = func_name_of(func)
    info["func_name"] = fname

    # (1) 상단 — 첫 함수 정의 전까지
    first_fn = min((s for _, s, _ in funcs), default=None)
    stop = text.count("\n", 0, first_fn) if first_fn is not None else None
    sec_top = top_matter(text, stop_line=stop)

    # (2) 대상 함수가 언급하는 타입 정의
    idents = set(IDENT_RE.findall(func))
    types = []
    for name, s, e in find_blocks(text, TYPE_RE):
        if not name:
            m = ANON_NAME_RE.match(text[e:e + 120])
            name = m.group(1) if m else ""
        if name and name in idents and (e - s) < 8000:
            end = e
            if text[e:e + 120].lstrip().startswith(("*", name)) or ";" in text[e:e + 120]:
                end = e + text[e:e + 120].find(";") + 1 if ";" in text[e:e + 120] else e
            types.append(text[s:max(end, e)])
    sec_types = "\n\n".join(types[:12])

    # (3) 같은 파일에서 대상 함수를 호출하는 지점 ±20줄
    callers = []
    if fname:
        pat = re.compile(r"\b" + re.escape(fname) + r"\s*\(")
        for i, ln in enumerate(lines):
            if not pat.search(ln):
                continue
            if s_line <= i <= e_line:      # 자기 자신(정의부·재귀)은 제외
                continue
            a, b = max(0, i - CALLER_WINDOW), min(len(lines), i + CALLER_WINDOW + 1)
            callers.append("\n".join(lines[a:b]))
            if len(callers) >= 6:
                break
    sec_callers = "\n\n/* ---- */\n\n".join(callers)

    # (4) 대상 함수가 호출하는 같은 파일 내 함수 본문
    called = {c for c in CALL_RE.findall(func) if c not in KEYWORDS and c != fname}
    bodies, seen = [], set()
    for name, s, e in funcs:
        if name in called and name not in seen and (e - s) < 12000:
            if span and s == span[0]:
                continue
            seen.add(name)
            bodies.append(text[s:e])
        if len(bodies) >= 8:
            break
    sec_callees = "\n\n".join(bodies)

    info.update(n_types=len(types), n_callers=len(callers), n_callees=len(bodies))
    return {"top": sec_top, "types": sec_types, "callers": sec_callers, "callees": sec_callees}, info


# ── 프롬프트 조립 ────────────────────────────────────────────────────────────
SECTION_TITLE = {
    "top": "// ---- file header (includes, macros, constants) ----",
    "types": "// ---- type definitions referenced by the target function ----",
    "callers": "// ---- call sites of the target function in this file ----",
    "callees": "// ---- functions called by the target function (same file) ----",
}
DROP_ORDER = ["callees", "callers", "types", "top"]   # 8k 초과 시 버리는 순서


def ctx_text(sections: dict[str, str]) -> str:
    parts = [f"{SECTION_TITLE[k]}\n{sections[k]}" for k in ("top", "types", "callers", "callees") if sections.get(k)]
    return "\n\n".join(parts)


def make_prompt(language: str, context: str, func: str | None) -> str:
    head = f"Analyze the following {language} code for security vulnerabilities."
    blocks = [head, ""]
    if context:
        blocks += [f"Surrounding file context (same file, for reference):", "",
                   f"```{language}", context, "```", ""]
    if func is not None:
        blocks += ["Target function to analyze:", "",
                   f"```{language}", func, "```", ""]
    blocks.append(TAIL)
    return "\n".join(blocks)


def main() -> None:
    split = sys.argv[1] if len(sys.argv) > 1 else "primevul_report"
    suffix = "" if split == "primevul_report" else "_" + split.split("_")[-1]
    CACHE.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(exist_ok=True)

    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained("unsloth/Qwen3.5-9B")
    ntok = lambda s: len(tok(s, add_special_tokens=False)["input_ids"])

    report = [json.loads(l) for l in (DATA / f"{split}.jsonl").open()]
    raw = [json.loads(l) for l in (DATA / "raw" / "primevul_test_paired.jsonl").open()]
    by_idx = {r["idx"]: i for i, r in enumerate(raw)}

    stats = Counter()
    records: list[dict] = []

    # ── 1) 케이스별 문맥 수집 ────────────────────────────────────────────────
    def work(row: dict) -> dict:
        meta = row["meta"]
        vuln_idx = int(meta["pair_id"].rsplit("_", 1)[1])
        i = by_idx.get(vuln_idx)
        rec = {"meta": meta, "t0_prompt": row["prompt"], "ok": False, "reason": ""}
        if i is None:
            rec["reason"] = "raw_idx_missing"
            return rec
        # build_external_bench.py와 동일한 짝 규칙: 짝수 인덱스부터 연속 2행이 한 쌍
        j = i + 1 if i % 2 == 0 else i - 1
        pair = [raw[i], raw[j]] if 0 <= j < len(raw) and raw[j]["commit_id"] == raw[i]["commit_id"] else [raw[i]]
        want = 1 if meta["label"] == "vuln" else 0
        src = next((r for r in pair if r["target"] == want), None)
        if src is None:
            rec["reason"] = "pair_broken"
            return rec
        rec["func"] = src["func"].strip()
        rec["language"] = "C++" if src["file_name"].rsplit(".", 1)[-1].lower() in \
            {"cc", "cpp", "cxx", "hpp", "hh", "c++"} else "C"

        repo = repo_of(src.get("project_url", ""))
        if not repo:
            rec["reason"] = "no_repo_url"
            return rec
        cm = commit_meta(repo, src["commit_id"])
        if cm is None:
            rec["reason"] = "commit_api_fail"
            return rec
        # 취약본은 부모 시점, 패치본은 fix 커밋 시점
        sha = cm["parent"] if want == 1 else src["commit_id"]
        if sha is None:
            rec["reason"] = "no_parent"
            return rec
        base = str(src.get("file_name") or "")
        cands = [p for p in cm["files"] if p.rsplit("/", 1)[-1] == base]
        if not cands:
            # PrimeVul은 file_name이 결측("None")인 행이 꽤 있다 → 커밋이 건드린 소스 파일을
            # 직접 열어 대상 함수가 들어 있는 파일을 찾는다. 파일 수가 많으면 포기(비용 상한).
            srcs = [p for p in cm["files"] if p.rsplit(".", 1)[-1].lower() in CODE_EXT]
            if not srcs or len(srcs) > 12:
                rec["reason"] = "path_not_in_commit"
                return rec
            cands = srcs
        text = None
        fn = func_name_of(rec["func"])
        for p in cands:
            t = file_at(repo, sha, p)
            if t and (t.find(rec["func"]) >= 0 or (fn and re.search(r"\b" + re.escape(fn) + r"\s*\(", t))):
                text, rec["path"] = t, p
                break
        if text is None:
            rec["reason"] = "file_fetch_fail"
            return rec
        sections, info = build_context(text, rec["func"])
        rec["sections"], rec["info"], rec["sha"], rec["repo"] = sections, info, sha, repo
        rec["ok"] = True
        return rec

    t0 = time.time()
    flags = {"rate_limited": False}

    def safe_work(row: dict) -> dict:
        if flags["rate_limited"]:
            return {"meta": row["meta"], "t0_prompt": row["prompt"], "ok": False, "reason": "rate_limited"}
        try:
            return work(row)
        except RateLimited:
            flags["rate_limited"] = True     # 대기하지 않고 그 시점까지로 확정 (사양서 §7)
            return {"meta": row["meta"], "t0_prompt": row["prompt"], "ok": False, "reason": "rate_limited"}
        except Exception as e:
            return {"meta": row["meta"], "t0_prompt": row["prompt"], "ok": False,
                    "reason": f"exc_{type(e).__name__}"}

    with ThreadPoolExecutor(max_workers=8) as ex:
        records = list(ex.map(safe_work, report))
    rate_limited = flags["rate_limited"]
    print(f"[collect] {len(records)}건 {time.time()-t0:.0f}s rate_limited={rate_limited}", flush=True)

    for r in records:
        stats["ok" if r["ok"] else f"fail_{r['reason']}"] += 1
        if r["ok"] and not r["info"]["located"]:
            stats["located_fail"] += 1

    # 함수 위치를 못 찾으면 호출부/호출대상이 신뢰 불가 → 실패로 처리(모든 arm에서 제외)
    for r in records:
        if r["ok"] and not r["info"]["located"]:
            r["ok"], r["reason"] = False, "func_not_located"

    # ── 2) 쌍 단위 필터: 한쪽이라도 실패하면 그 쌍 전체를 모든 arm에서 제외 ──
    ok_by_pair: dict[str, list[dict]] = {}
    for r in records:
        ok_by_pair.setdefault(r["meta"]["pair_id"], []).append(r)
    keep_pairs = {p for p, rs in ok_by_pair.items() if len(rs) == 2 and all(x["ok"] for x in rs)}
    stats["pairs_total"] = len(ok_by_pair)
    stats["pairs_kept"] = len(keep_pairs)
    kept = [r for r in records if r["meta"]["pair_id"] in keep_pairs]

    # ── 3) 8k 상한 적용 ─────────────────────────────────────────────────────
    for r in kept:
        secs = dict(r["sections"])
        full = ntok(make_prompt(r["language"], ctx_text(secs), r["func"]))
        dropped = []
        while ntok(make_prompt(r["language"], ctx_text(secs), r["func"])) > MAX_CTX_TOKENS and DROP_ORDER:
            for k in DROP_ORDER:
                if secs.get(k):
                    secs[k] = ""
                    dropped.append(k)
                    break
            else:
                break
        # 그래도 초과하면(대상 함수 자체가 김) 남은 문맥을 줄 단위로 자른다
        while ntok(make_prompt(r["language"], ctx_text(secs), r["func"])) > MAX_CTX_TOKENS:
            ct = ctx_text(secs).splitlines()
            if not ct:
                break
            keep_n = max(0, int(len(ct) * 0.8))
            if keep_n == len(ct):
                keep_n = len(ct) - 1
            merged = "\n".join(ct[:keep_n])
            secs = {"top": merged, "types": "", "callers": "", "callees": ""}
            if keep_n == 0:
                break
        r["sections_capped"] = secs
        r["ctx"] = ctx_text(secs)
        r["tok_full"], r["tok_capped"] = full, ntok(make_prompt(r["language"], r["ctx"], r["func"]))
        r["dropped_sections"] = dropped
        if dropped:
            stats["truncated_cases"] += 1

    # ── 4) T1-shuf: 다른 케이스의 문맥을 같은 분량만큼 ────────────────────────
    rnd = random.Random(SEED)
    n = len(kept)
    order = list(range(n))
    for _ in range(200):                      # derangement (자기 자신 금지)
        rnd.shuffle(order)
        if all(order[i] != i for i in range(n)):
            break
    # 같은 쌍끼리도 섞이지 않도록 한 번 더 확인
    for i in range(n):
        if kept[order[i]]["meta"]["pair_id"] == kept[i]["meta"]["pair_id"]:
            j = (i + n // 3) % n
            order[i], order[j] = order[j], order[i]

    for i, r in enumerate(kept):
        donor = kept[order[i]]
        target_tokens = max(0, r["tok_capped"] - ntok(make_prompt(r["language"], "", r["func"])))
        dl = donor["ctx"].splitlines()
        lo, hi = 0, len(dl)
        while lo < hi:                        # 줄 수를 이분탐색으로 맞춘다
            mid = (lo + hi + 1) // 2
            if ntok("\n".join(dl[:mid])) <= target_tokens:
                lo = mid
            else:
                hi = mid - 1
        r["ctx_shuf"] = "\n".join(dl[:lo])
        r["shuf_donor"] = donor["meta"]["pair_id"] + "/" + donor["meta"]["label"]

    # ── 5) arm별 파일 출력 ──────────────────────────────────────────────────
    arms = {
        "T0":        lambda r: r["t0_prompt"],
        "T1":        lambda r: make_prompt(r["language"], r["ctx"], r["func"]),
        "T1shuf":    lambda r: make_prompt(r["language"], r["ctx_shuf"], r["func"]),
        "T1nofunc":  lambda r: make_prompt(r["language"], r["ctx"], None),
    }
    for arm, fn in arms.items():
        p = DATA / f"ctx_{arm}{suffix}.jsonl"
        with p.open("w") as f:
            for r in kept:
                f.write(json.dumps({"prompt": fn(r), "meta": r["meta"]}, ensure_ascii=False) + "\n")
        print(f"  {arm}: {len(kept)}건 → {p}")

    # 진단 원본(정성 확인·리포트용)
    with (OUT / f"ctx_collect_detail{suffix}.jsonl").open("w") as f:
        for r in kept:
            f.write(json.dumps({
                "pair_id": r["meta"]["pair_id"], "label": r["meta"]["label"],
                "repo": r["repo"], "sha": r["sha"], "path": r.get("path"),
                "language": r["language"], "info": r["info"],
                "tok_full": r["tok_full"], "tok_capped": r["tok_capped"],
                "dropped_sections": r["dropped_sections"],
                "shuf_donor": r["shuf_donor"],
                "ctx_chars": len(r["ctx"]), "func_chars": len(r["func"]),
            }, ensure_ascii=False) + "\n")

    toks = [r["tok_capped"] for r in kept]
    summary = {
        "split": split,
        "n_report_rows": len(report), "n_kept_rows": len(kept),
        "n_pairs_total": stats["pairs_total"], "n_pairs_kept": stats["pairs_kept"],
        "collect_success_rate": round(stats["pairs_kept"] / max(1, stats["pairs_total"]), 4),
        "truncated_cases": stats["truncated_cases"],
        "truncation_rate": round(stats["truncated_cases"] / max(1, len(kept)), 4),
        "tok_capped_mean": round(sum(toks) / max(1, len(toks)), 1),
        "tok_capped_max": max(toks) if toks else 0,
        "tok_full_mean": round(sum(r["tok_full"] for r in kept) / max(1, len(kept)), 1),
        "rate_limited": rate_limited,
        "failures": {k: v for k, v in sorted(stats.items()) if k.startswith("fail_") or k == "located_fail"},
    }
    (OUT / f"ctx_collect_stats{suffix}.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
