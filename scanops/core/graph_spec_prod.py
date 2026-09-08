"""프로덕션 레포단위 그래프+taint 파이프라인 (2026-08-23, 베타 배포).

연구용 `rebuild/graph_spec_llm.py` + `rebuild/graph_spec_to_joern.py` +
`rebuild/graph_spec_critic_r3.py`의 핵심 로직(스펙 생성 규칙, 검증 규칙, critic 판정 규칙)을
그대로 옮긴 것이다 — 프롬프트·룰 문구를 바꾸려면 두 곳(연구/서빙) 다 고쳐야 한다.
연구 스크립트는 로컬 파일(candidates json, raw jsonl)을 디스크에 쓰며 진행하지만, 이건
API 요청 하나 안에서 전부 메모리로 처리한다(레포 파일이 이미 요청 본문에 들어있으므로).

호출 순서 (analyze_repo):
  1) 고정 룰만 쓰는 shadow/offline이면 바로 spec.tsv 조립(Qwen/DashScope 불필요)
  2) 룰생성 또는 enforce가 필요할 때만 Joern mode=candidates로 후보 추출
  3) 룰생성 활성+Qwen 가용 시 캐시미스 제안; enforce일 때만 동적 룰을 spec에 추가
  4) Joern 워커 mode=taint — 조립한 spec으로 실제 taint 쿼리, line 단위 findings
  5) critic 활성+Qwen 가용 시에만 evidence 검증 통과분을 오탐필터로 호출
  6) §23 PRODUCTION_failsafe: TRUE/UNCERTAIN/unjudged/evidence_mismatch를 살리고,
     실제 제시 문맥의 line을 근거로 든 high-confidence FALSE만 제거

**절대 스캔 전체를 죽이지 않는다.** 이 모듈의 모든 외부 호출은 개별로 감싸여 있고,
실패하면 그 레포는 그냥 그래프 보강 없이(v1 LLM 단독) 나간다 — `api_rebuild.py`가
`analyze_repo()`를 호출할 때도 통째로 try/except로 감싼다.
"""
from __future__ import annotations

import json
import hashlib
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from joern.langmap import resolve as _resolve_lang  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]

ENABLED = os.getenv("GRAPH_SPEC_ENABLED", "on") == "on"
# 백엔드가 보내는 language 문자열은 "Node.js / Express" 같은 표시용 문자열이다
# (scanops-backend GithubScanService.EXT_TO_LANG) — joern/langmap.py가 이미 이걸
# JSSRC로 정규화해주므로 그대로 재사용한다(문자열을 여기서 또 하드코딩하지 않는다).
# 2026-09-05 ablation 파일럿(§Phase 1-8 arm C/D): JAVASRC 를 추가했다. dump_candidates.sc
# 는 애초에 lang 파라미터를 그대로 importCode 에 넘길 뿐 언어를 하드코딩하지 않았고
# (PHASE1-8_ABLATION_ARM_SURVEY.md §1 확인), taint_spec.sc 는 이미 4라운드째 lang=JAVASRC
# 로 돌고 있다(langmap.py 의 VERIFIED 집합에도 JAVASRC 가 있음) — 즉 Joern 레벨에서
# Java 를 막는 이유가 없었다. **기존 JSSRC 판정은 안 건드렸다**(OR 로만 확장, 부분집합
# 관계라 JS/TS 입력에 대한 반환값은 절대 안 바뀐다).
def is_supported_lang(language: str) -> bool:
    resolved = _resolve_lang(language or "")
    return bool(resolved) and resolved[1] in ("JSSRC", "JAVASRC")

RUNPOD_API_KEY = os.getenv("RUNPOD_API_KEY", "")
JOERN_ENDPOINT_ID = os.getenv("RUNPOD_JOERN_ENDPOINT_ID", "")
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY", "")
DASHSCOPE_BASE_URL = os.getenv(
    "DASHSCOPE_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
).rstrip("/")
LLM_MODEL = os.getenv("GRAPH_SPEC_LLM_MODEL", "qwen3.8-max")
# 2026-08-23: Joern을 RunPod 서버리스로 올렸더니 워커가 ready 상태로 뜨고도 큐 job을
# 전혀 안 가져가는 원인불명 문제가 있었다(§24-6). 콘솔 로그 접근 없이는 못 고쳐서
# 임시로 상시 기동 Pod + 온프레미스 HTTP 모드(handler_joern.py 진입점 2)로 우회한다.
# 이 값이 있으면 RunPod 서버리스 대신 이 URL을 직접 호출한다.
JOERN_HTTP_URL = os.getenv("JOERN_HTTP_URL", "")
RUNPOD_POLL_INTERVAL = float(os.getenv("RUNPOD_POLL_INTERVAL", "2.0"))
JOERN_TIMEOUT = int(os.getenv("GRAPH_SPEC_JOERN_TIMEOUT", "600"))
# Batch-20 G1 needed a 600-second retry window; a 300-second production timeout caused all first
# G3 batches to be discarded despite the same payload eventually succeeding in the evaluator.
RULEGEN_TIMEOUT = int(os.getenv("GRAPH_SPEC_RULEGEN_TIMEOUT", "600"))
# Accuracy-first default: do not silently discard rare APIs in a large Java repository.
# Operators may set a positive emergency cap, but the default processes every cache miss.
MAX_FRESH_ITEMS = int(os.getenv("GRAPH_SPEC_MAX_FRESH_ITEMS", "0"))
# G1 41-item full rerun at 20: macro-F1/sink recall/exact-CWE recall all 1.0,
# missing 0 (2026-09-06). Larger batches cut repository-scale request count.
RULEGEN_BATCH = int(os.getenv("GRAPH_SPEC_RULEGEN_BATCH", "20"))
CRITIC_BATCH = int(os.getenv("GRAPH_SPEC_CRITIC_BATCH", "4"))
LLM_MAX_WORKERS = max(1, int(os.getenv("GRAPH_SPEC_LLM_MAX_WORKERS", "6")))
# Rule proposal is an optional side channel. Keeping the historical default on means
# configured deployments still populate the shadow cache, while an offline deployment
# can run the fixed Java CPG rules without a DashScope credential.
RULEGEN_ENABLED = os.getenv("GRAPH_SPEC_RULEGEN_ENABLED", "on").lower() == "on"
RULEGEN_CONTEXT_VERSION = os.getenv("GRAPH_SPEC_RULEGEN_CONTEXT", "v1").strip().lower()
if RULEGEN_CONTEXT_VERSION not in ("v1", "v2"):
    RULEGEN_CONTEXT_VERSION = "v1"
DYNAMIC_SANITIZER_ENABLED = os.getenv("GRAPH_SPEC_DYNAMIC_SANITIZER_ENABLED", "off").lower() == "on"
DYNAMIC_PROPAGATION_ENABLED = os.getenv("GRAPH_SPEC_DYNAMIC_PROPAGATION_ENABLED", "off").lower() == "on"
CRITIC_ENABLED = os.getenv("GRAPH_SPEC_CRITIC_ENABLED", "off").lower() == "on"
CRITIC_FALSE_CONFIDENCE = os.getenv(
    "GRAPH_SPEC_CRITIC_FALSE_CONFIDENCE", "high").strip().lower()
DYNAMIC_RULE_MODE = os.getenv("GRAPH_SPEC_DYNAMIC_RULE_MODE", "shadow").strip().lower()
if DYNAMIC_RULE_MODE not in ("shadow", "enforce"):
    DYNAMIC_RULE_MODE = "shadow"

API_CACHE_PATH = Path(os.getenv("GRAPH_SPEC_API_CACHE", str(ROOT / "rebuild" / "out" / "graph_spec_api_cache.json")))


def qwen_runtime_ready() -> bool:
    """Whether the pinned Qwen rule/critic transport is usable in this process."""
    return bool(DASHSCOPE_API_KEY) and LLM_MODEL == "qwen3.8-max"


def runtime_metadata() -> dict[str, Any]:
    """Expose configured versus effective optional features for logs/health endpoints."""
    qwen_ready = qwen_runtime_ready()
    return {
        "engine_enabled": ENABLED,
        "joern_configured": bool(JOERN_HTTP_URL) or bool(RUNPOD_API_KEY and JOERN_ENDPOINT_ID),
        "fixed_rules_require_qwen": False,
        "dynamic_rule_mode": DYNAMIC_RULE_MODE,
        "rulegen_context": RULEGEN_CONTEXT_VERSION,
        "dynamic_sanitizer_enabled": DYNAMIC_SANITIZER_ENABLED,
        "dynamic_propagation_enabled": DYNAMIC_PROPAGATION_ENABLED,
        "rulegen": {
            "enabled": RULEGEN_ENABLED,
            "qwen_ready": qwen_ready,
            "effective": RULEGEN_ENABLED and qwen_ready,
            "model": LLM_MODEL,
        },
        "critic": {
            "enabled": CRITIC_ENABLED,
            "qwen_ready": qwen_ready,
            "effective": CRITIC_ENABLED and qwen_ready,
            "model": LLM_MODEL,
        },
    }

# ── RunPod 호출 (async run + poll — runsync 타임아웃 회피) ──────────────────

def _runpod_call(endpoint_id: str, payload: dict, timeout: int) -> dict:
    if not RUNPOD_API_KEY or not endpoint_id:
        raise RuntimeError("runpod endpoint/key not configured")
    headers = {"Authorization": f"Bearer {RUNPOD_API_KEY}", "Content-Type": "application/json"}
    base = f"https://api.runpod.ai/v2/{endpoint_id}"
    r = requests.post(f"{base}/run", headers=headers, json={"input": payload}, timeout=30)
    r.raise_for_status()
    job_id = r.json()["id"]
    t0 = time.time()
    while time.time() - t0 < timeout:
        rr = requests.get(f"{base}/status/{job_id}", headers=headers, timeout=30)
        rr.raise_for_status()
        d = rr.json()
        status = d.get("status")
        if status == "COMPLETED":
            return d.get("output") or {}
        if status in ("FAILED", "CANCELLED", "TIMED_OUT"):
            raise RuntimeError(f"runpod job {status}: {d.get('error')}")
        time.sleep(RUNPOD_POLL_INTERVAL)
    # 타임아웃 — 취소 시도(비용 절감), 예외로 상위에 알림
    try:
        requests.post(f"{base}/cancel/{job_id}", headers=headers, timeout=10)
    except Exception:  # noqa: BLE001
        pass
    raise TimeoutError(f"runpod job {job_id} exceeded {timeout}s")


def call_joern_repo(mode: str, language: str, files: list[dict], **kw) -> dict:
    payload = {"mode": mode, "language": language, "files": files, **kw}
    if JOERN_HTTP_URL:
        r = requests.post(f"{JOERN_HTTP_URL.rstrip('/')}/joern/repo",
                          json={"job_id": f"prod_{int(time.time()*1000)}", **payload},
                          timeout=JOERN_TIMEOUT)
        r.raise_for_status()
        return r.json()
    return _runpod_call(JOERN_ENDPOINT_ID, payload, JOERN_TIMEOUT)


def call_rulegen(system: str, user: str, n_predict: int) -> str:
    """CPG 룰 생성과 critic은 Qwen3.8-Max(DashScope)만 사용한다."""
    if LLM_MODEL != "qwen3.8-max":
        raise RuntimeError("GRAPH_SPEC_LLM_MODEL must be qwen3.8-max")
    if not DASHSCOPE_API_KEY:
        raise RuntimeError("DASHSCOPE_API_KEY is not configured")
    r = requests.post(
        f"{DASHSCOPE_BASE_URL}/chat/completions",
        headers={"Authorization": f"Bearer {DASHSCOPE_API_KEY}",
                 "Content-Type": "application/json"},
        json={"model": LLM_MODEL,
              "messages": [{"role": "system", "content": system},
                           {"role": "user", "content": user}],
              "max_tokens": n_predict, "temperature": 0.0,
              "enable_thinking": False},
        timeout=RULEGEN_TIMEOUT,
    )
    r.raise_for_status()
    data = r.json()
    return data["choices"][0]["message"].get("content", "") or ""


# ── §21 API 캐시 (rebuild/graph_spec_to_joern.py 와 동일 형식·파일 공유) ────

def load_api_cache() -> dict:
    if API_CACHE_PATH.exists():
        return json.loads(API_CACHE_PATH.read_text())
    return {}


def cache_key(kind: str, name: str, frontend: str | None = None) -> str:
    """언어별 API 의미 충돌을 막는다. 기존 JS 캐시는 lookup에서만 호환한다."""
    prefix = f"{frontend}:" if frontend else ""
    return f"{prefix}{kind}:{name}"


def _cache_lookup(cache: dict, item: dict, frontend: str) -> dict | None:
    entry = cache.get(cache_key(item["kind"], item["name"], frontend))
    if entry is None and frontend == "JSSRC":
        entry = cache.get(cache_key(item["kind"], item["name"]))
    return entry


def update_api_cache(good: list[dict], repo_tag: str, frontend: str) -> None:
    cache = load_api_cache()
    added = 0
    for r in good:
        cand = r.get("_candidate")
        if not cand:
            continue
        k = cache_key(cand["kind"], cand["name"], frontend)
        if k in cache:
            continue
        # 2026-09-05 8라운드 §2: arg_pattern 추가 — 없으면 arg_literal(_full) 룰이 캐시를
        # 거쳐 오는 순간 validate() 의 arg_pattern 필수 체크에 걸려 조용히 탈락한다.
        entry = {kk: r[kk] for kk in ("role", "cat", "cwe", "match", "pattern", "arg_pattern",
                                      "arg_count",
                                      "endpoint", "applies_to", "propagation", "confidence", "why",
                                      "rule_id", "_provenance", "_enforce_eligible")
                 if kk in r}
        entry["_first_seen_repo"] = repo_tag
        entry["_reviewed_by_human"] = False
        cache[k] = entry
        added += 1
    if added:
        API_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        API_CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False, indent=2, sort_keys=True))


# ── 룰생성 프롬프트 (rebuild/graph_spec_llm.py 와 동일) ─────────────────────

CATS = {
    "sqli": "CWE-89", "cmdi": "CWE-78", "xss": "CWE-79", "pathtraver": "CWE-22",
    "ssrf": "CWE-918", "deser": "CWE-502", "codei": "CWE-94", "redirect": "CWE-601",
    "nosqli": "CWE-943", "logforge": "CWE-117", "sensitive": "CWE-200",
    "accesscontrol": "CWE-284", "weakcrypto": "CWE-327", "proto": "CWE-1321",
    # 2026-09-05 6라운드 파일럿 §2: Juliet Tier A/B 38개 CWE 중 gen_spec_tsv.SINKS 에는
    # 있지만 CATS 엔 없던 카테고리를, "그 카테고리를 쓰는 Juliet CWE 가 정확히 하나뿐인
    # 것"만 추가했다 — 그 경우엔 CWE 번호가 모호하지 않다(예: configinj 는 CWE-15 하나만
    # 씀). infoexpose(CWE-209/526/533/534/598 5개 공유)/pathtraversal(CWE-23/36 이 공유,
    # 게다가 기존 pathtraver 키가 이미 일반 부모 CWE-22 로 CWE-23/36 과 다름)/proccontrol
    # (CWE-114/382 공유, 둘은 분류상 무관한 취약점인데 gen_spec_tsv.py 가 편의상 한
    # 카테고리로 묶어놓은 것) 은 CWE 번호 하나로 못 박을 수 없어서 **안 추가했다** —
    # CATS 는 (카테고리 -> CWE 1개) 구조라 억지로 넣으면 findings 에 틀린 CWE 가 찍힌다.
    # 결정 필요 항목으로 SUMMARY 에 남김(PHASE1-8_ABLATION_PILOT_R2_RESULTS.md §6).
    "configinj": "CWE-15", "fmtstr": "CWE-134", "hardcoded": "CWE-259",
    "httprs": "CWE-113", "ldapi": "CWE-90", "obsolete": "CWE-477",
    "plaintext_password": "CWE-256", "reflection": "CWE-470", "xpathi": "CWE-643",
    # 다대다 카테고리는 아래 CATEGORY_CWES가 실제 CWE를 검증한다. 여기 값은
    # 하위 호환용 대표값일 뿐 프로덕션 출력으로 강제하지 않는다.
    "infoexpose": "CWE-209", "proccontrol": "CWE-114",
}

# 단일 대표 CWE만 강제하면 weakcrypto/xss/sensitive 같은 다대다 카테고리의 세부 CWE가
# 사라진다. LLM이 낸 CWE를 아래 허용 집합으로 검증한 뒤 그대로 보존한다.
CATEGORY_CWES = {
    **{cat: {cwe} for cat, cwe in CATS.items()},
    "weakcrypto": {"CWE-321", "CWE-327", "CWE-328", "CWE-338", "CWE-759", "CWE-760"},
    "pathtraver": {"CWE-22", "CWE-23", "CWE-36"},
    "sensitive": {"CWE-200", "CWE-315", "CWE-319", "CWE-539"},
    "xss": {"CWE-79", "CWE-80", "CWE-81", "CWE-83"},
    "infoexpose": {"CWE-209", "CWE-526", "CWE-533", "CWE-534", "CWE-598"},
    "proccontrol": {"CWE-114", "CWE-382"},
}

# 2026-09-05 9라운드 §1: to_tsv() 의 cwe_hint 를 "이 카테고리 전부"가 아니라 "실제로
# 여러 CWE 를 아우르는 걸로 이미 알려진 카테고리"에만 적용하기 위한 화이트리스트.
# benchmarks/juliet-java/gen_spec_tsv.py 의 SINKS(cat -> CWE 목록)를 다시 훑어서
# CATEGORY_CWES 에 있는 카테고리 키 중 실제로 둘 이상의 CWE 가 공유하는 것만 추출했다:
#   weakcrypto  : CWE-321/327/328/338/759/760 (6개 공유 — 8라운드에 CWE-327/338 실측 확인)
#   pathtraver  : CWE-22 가 대표값이지만 gen_spec_tsv.py 는 CWE-23/36 도 이 계열로 씀
#   sensitive   : CATS 대표값은 CWE-200 이지만 gen_spec_tsv.py 는 CWE-315/319/539 에 씀
#   xss         : CATS 대표값은 CWE-79 지만 gen_spec_tsv.py 는 CWE-80/81/83 에 씀(이번
#                 파일럿 스코프 밖, 8라운드까지 미검증 — 다음에 xss 계열 CWE 를 스코프에
#                 넣을 때 실측 필요)
# 이 집합에 없는 카테고리(sqli/cmdi 등)는 대표 CWE가 하나뿐이므로 cwe_hint를 무시한다.
# infoexpose/proccontrol도 이제 허용하며 CATEGORY_CWES로 세부 CWE를 검증한다.
CWE_HINT_ELIGIBLE_CATS = {"weakcrypto", "pathtraver", "sensitive", "xss"}

RULEGEN_SYSTEM = """You are a static-analysis expert writing taint-tracking specifications for the Joern code property graph engine.

You will be given a batch of items extracted from ONE repository: most are API call names (with resolved method-full-names and short usage snippets), and some are PROPERTY-WRITE TARGETS (kind="property_write_target") — a field name that appears as the left-hand side of an assignment somewhere in the repo, e.g. for `el.innerHTML = x` the item is the bare field name `innerHTML`, not a call. For each item you decide what role it plays in taint analysis and emit a machine-readable rule.

HARD RULES — a violation makes the whole answer unusable:
1. Rules must describe GENERAL framework / library / language API behaviour. Never write a rule that keys on a source-file path, a project-specific file name, a line number, or a one-off local identifier. If an API is only meaningful because of where it happens to appear in this repository, label it "none".
2. Match `name` against the bare call name; match `full` against the method-full-name (library-qualified). Use `full` when the receiver/library matters (ORM query builders, chained calls, package-scoped constructors) — this is required for ORM and chained APIs. Use `assign_field` ONLY for kind="property_write_target" items — pattern is matched against the bare field name being assigned to (e.g. `^innerHTML$|^outerHTML$` for known DOM XSS sinks). Never use `assign_field` for kind="call" items, and never use `name`/`full` for kind="property_write_target" items.
2b. Use `exists` (bare call name) or `exists_full` (method-full-name) for a sink role ONLY when the call itself is the danger and it does NOT take an attacker-controlled argument to be exploitable — e.g. an insecure PRNG call/constructor, loading a native library, an obsolete/forbidden API whose mere invocation is the flaw. These sinks are reported whenever the call is present in the code, with no source needed and no taint flow required — do NOT use `exists`/`exists_full` for anything that needs an attacker-controlled value to reach it (that is `name`/`full` instead). When you use `exists`/`exists_full`, omit `propagation` (there is nothing flowing into a presence-only sink).
2c. Use `arg_literal` (bare call name) or `arg_literal_full` (method-full-name) for a sink role ONLY when the call is dangerous or safe depending on a FIXED LITERAL VALUE passed as one of its arguments — not on whether the argument is attacker-controlled. Classic case: an algorithm-selection API where one literal name is weak and another is strong (e.g. `Cipher.getInstance("DES")` is a weak-crypto sink but `Cipher.getInstance("AES")` is not — the danger is which constant string was passed, not where it came from). When you use `arg_literal`/`arg_literal_full`, you MUST also emit `arg_pattern`: a Java regex matched against the literal text of the dangerous argument value(s) (e.g. `"DES|DESede"`). `pattern` still identifies the call itself (name or full method name) exactly as for `name`/`full`; `arg_pattern` is the extra condition on the argument. Omit `propagation` for these too (no taint flow is being modeled — the argument is read as a literal, not traced).
2d. Use `arg_count` or `arg_count_full` for a sink role ONLY when a dangerous obsolete overload is distinguished from its safe replacement by positional argument count. Emit `arg_count` as a positive integer. Omit `propagation`.
3. Regex is Java syntax. Anchor name patterns (`^...$`) unless you deliberately want a family.
4. Be precise, not maximal. A sink that fires on every `get`/`send`/`write` destroys precision. Prefer `full` patterns that pin the library. For property_write_target items, only mark as sink the small set of GENUINELY dangerous general write targets (e.g. DOM innerHTML/outerHTML family) — most property writes are role="none".
5. Only emit `propagation` for EXTERNAL library APIs whose taint behaviour Joern cannot see inside (argument -> return value, argument -> receiver). Index 0 = receiver/this, 1..n = positional arguments, "return" = return value. Not applicable to `exists`/`exists_full`/`arg_literal`/`arg_literal_full` sinks (see 2b/2c).

Output ONE JSON array, no prose, no markdown fence. One object per input API, in the same order, each:
{"id": <int, echo the input id>,
 "role": "sink" | "source" | "sanitizer" | "none",
 "cat": "<category key, sink only>",
 "cwe": "CWE-nnn (sink only)",
 "match": "name" | "full" | "assign_field" | "exists" | "exists_full" | "arg_literal" | "arg_literal_full" | "arg_count" | "arg_count_full",
 "pattern": "<Java regex>",
 "arg_pattern": "<Java regex, ONLY for match=arg_literal/arg_literal_full — matched against the literal argument value>",
 "arg_count": <positive integer, ONLY for match=arg_count/arg_count_full>,
 "applies_to": ["<cat>", ...],
 "propagation": [{"from": <int|"return">, "to": <int|"return">}],
 "confidence": "high" | "med" | "low",
 "why": "<max 15 words>"}

Category keys and allowed CWE values (use exactly these):
""" + "\n".join(f"  {k} = {', '.join(sorted(v))}" for k, v in CATEGORY_CWES.items()) + """

role meanings:
  sink      — reaching this call with attacker-controlled data is the vulnerability
  source    — this call returns attacker-controlled data (request input, env, argv, stdin, file/DB reads of user data)
  sanitizer — this call neutralises tainted data for the categories in applies_to
  none      — irrelevant to taint analysis (the correct answer for most APIs)
"""

RULEGEN_USER_TMPL = """Repository language: {lang}
Batch {bi}/{bn}. Label every API below.

{items}

Return the JSON array now."""

PATH_RE = re.compile(r"[A-Za-z0-9_./\-]+\.(ts|tsx|js|jsx|mjs|cjs|py|java|scala|go|rb|php)\b")


def norm_full(s: str) -> str:
    s = re.sub(r"[A-Za-z0-9_./\-]+\.(ts|tsx|js|jsx|mjs|cjs)::program", "<local>::program", s)
    return s


def strip_locs(code: str) -> str:
    return PATH_RE.sub("<path>", code)[:160]


PACKAGE_RE = re.compile(r"(?m)^\s*package\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*;")


def java_local_packages(files: list[dict] | None) -> set[str]:
    return {match.group(1) for item in (files or [])
            for match in PACKAGE_RE.finditer(item.get("content", ""))}


def _all_full_names_are_local(fulls: list[dict], packages: set[str]) -> bool:
    names = [str(item.get("full") or "") for item in fulls]
    resolved = [name for name in names if name and not name.startswith("<")]
    return bool(resolved) and len(resolved) == len(names) and all(
        any(name.startswith(package + ".") for package in packages) for name in resolved)


def build_items(cand: dict, frontend: str | None = None,
                files: list[dict] | None = None) -> list[dict]:
    """dump_candidates.sc 출력 → LLM 입력 항목. params kind는 보내지 않는다
    (taint_spec.sc가 frontend별 trust-boundary 정책으로 직접 처리한다)."""
    items = []
    local_packages = java_local_packages(files) if frontend == "JAVASRC" else set()
    for c in cand.get("calls", []):
        if frontend == "JAVASRC" and _all_full_names_are_local(c.get("fulls", []), local_packages):
            continue
        items.append({"kind": "call", "name": c["name"],
                      "fulls": list(dict.fromkeys(norm_full(f["full"]) for f in c["fulls"]))[:3],
                      "n": c["n"], "snippets": [strip_locs(x) for x in c["codes"][:2]]})
    if frontend != "JAVASRC":
        for a in cand.get("assigns", []):
            items.append({"kind": "assign", "name": a["field"], "fulls": [], "n": a["n"],
                          "snippets": [strip_locs(x) for x in a["codes"][:2]]})
    for i, it in enumerate(items):
        it["id"] = i
    return items


def fmt_item(it: dict) -> str:
    if it["kind"] == "assign":
        return json.dumps({"id": it["id"], "kind": "property_write_target", "name": it["name"],
                           "occurrences": it["n"], "snippets": it["snippets"]}, ensure_ascii=False)
    return json.dumps({"id": it["id"], "kind": "call", "name": it["name"],
                       "full_names": it["fulls"], "occurrences": it["n"],
                       "snippets": it["snippets"]}, ensure_ascii=False)


CWE_DESCRIPTIONS = {
    "CWE-15": "External control of system or configuration setting",
    "CWE-22": "Path traversal",
    "CWE-78": "OS command injection",
    "CWE-79": "Cross-site scripting",
    "CWE-89": "SQL injection",
    "CWE-90": "LDAP injection",
    "CWE-94": "Code injection",
    "CWE-113": "HTTP response splitting",
    "CWE-117": "Improper output neutralization for logs",
    "CWE-200": "Exposure of sensitive information",
    "CWE-284": "Improper access control",
    "CWE-327": "Use of a broken or risky cryptographic algorithm",
    "CWE-470": "Externally controlled input to select classes or code",
    "CWE-477": "Use of obsolete function",
    "CWE-502": "Deserialization of untrusted data",
    "CWE-601": "Open redirect",
    "CWE-643": "XPath injection",
    "CWE-918": "Server-side request forgery",
}

RULEGEN_V2_SYSTEM = """You generate precise Java taint-model proposals from structured facts extracted from a Joern CPG and source context.

The input is NOT a whole CPG. It contains exact call/method facts, endpoints, representative source windows, comments/JavaDoc when available, and a target CWE catalogue. Do not invent facts absent from the item.

Return one JSON array in input order, with no prose or markdown. Each object must contain:
{"id": <echo id>, "role": "sink"|"source"|"sanitizer"|"propagator"|"none",
 "cat": <allowed category for sinks>, "cwe": "CWE-nnn" for sinks,
 "match": "full" or "internal_parameter", "pattern": <anchored Java regex>,
 "endpoint": "return"|"receiver"|"call"|"arg:N",
 "applies_to": [<categories>] for sanitizers,
 "propagation": [{"from": <int|"return">, "to": <int|"return">}] for propagators,
 "confidence": "high"|"med"|"low", "why": <max 20 words>}.

Rules:
- Prefer none when resolution or context is insufficient.
- A call rule must use its exact resolved method_full_name and match=full. Never widen to a bare method name.
- A sink must name the exact dangerous argument (arg:N), receiver, or call-presence endpoint.
- A source must name return, receiver, or exact argument endpoint.
- internal_method_parameter items may only be source or none, use match=internal_parameter and their exact arg:N endpoint.
- A sanitizer is only valid with exact input/output behaviour and applies_to categories.
- A propagator is only valid for external APIs whose body is unavailable.
- Project-local names, file paths, line numbers, and repository-specific identifiers must not appear in pattern.

Examples:
Input resolved Runtime.exec arg 1 -> {"id":0,"role":"sink","cat":"cmdi","cwe":"CWE-78","match":"full","pattern":"^java\\.lang\\.Runtime\\.exec:java\\.lang\\.Process\\(java\\.lang\\.String\\)$","endpoint":"arg:1","confidence":"high","why":"command argument reaches process execution"}
Input resolved HttpServletRequest.getParameter -> {"id":1,"role":"source","match":"full","pattern":"^javax\\.servlet\\.http\\.HttpServletRequest\\.getParameter:java\\.lang\\.String\\(java\\.lang\\.String\\)$","endpoint":"return","confidence":"high","why":"returns request-controlled parameter"}
Input StringBuilder.append external body unavailable -> {"id":2,"role":"propagator","match":"full","pattern":"^java\\.lang\\.StringBuilder\\.append:java\\.lang\\.StringBuilder\\(java\\.lang\\.String\\)$","endpoint":"return","propagation":[{"from":1,"to":0},{"from":0,"to":"return"}],"confidence":"high","why":"append carries input through receiver and return"}
Input unresolved generic write -> {"id":3,"role":"none","match":"full","pattern":"^<unresolved.*$","endpoint":"call","confidence":"low","why":"receiver and overload unresolved"}
"""

RULEGEN_V2_USER_TMPL = """Repository language: Java
Candidate schema: scanops.rulegen-candidates.v2
Target CWE catalogue: {cwes}
Batch {bi}/{bn}. Label every item below.

{items}

Return the JSON array now."""


def _file_content(files: list[dict], path: str) -> str:
    normalized = (path or "").replace("\\", "/")
    for item in files or []:
        p = str(item.get("path") or "").replace("\\", "/")
        if p == normalized or normalized.endswith("/" + p) or p.endswith("/" + normalized):
            return str(item.get("content") or "")
    return ""


def _source_window(files: list[dict], path: str, line: int, radius: int = 5) -> str:
    content = _file_content(files, path)
    if not content or not isinstance(line, int) or line < 1:
        return ""
    lines = content.splitlines()
    start, end = max(0, line - 1 - radius), min(len(lines), line + radius)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end))[:2400]


def _javadoc_before(files: list[dict], path: str, line: int) -> str:
    content = _file_content(files, path)
    if not content or not isinstance(line, int) or line < 2:
        return ""
    prefix = "\n".join(content.splitlines()[:line - 1])
    match = re.search(r"/\*\*(.*?)\*/\s*(?:@[\w.]+(?:\([^\n]*\))?\s*)*$", prefix, re.S)
    return re.sub(r"(?m)^\s*\* ?", "", match.group(1)).strip()[:800] if match else ""


def _exact_pattern(full_name: str) -> str:
    return "^" + re.escape(full_name) + "$"


def build_items_v2(cand: dict, files: list[dict]) -> list[dict]:
    """Build exact-FQN Java candidates while preserving unresolved items for shadow audit."""
    items: list[dict] = []
    local_packages = java_local_packages(files)
    for call in cand.get("calls", []):
        full = str(call.get("method_full_name") or "")
        is_local = any(full.startswith(pkg + ".") for pkg in local_packages)
        if is_local:
            continue
        sites = []
        for site in (call.get("sites") or [])[:3]:
            path, line = str(site.get("file") or ""), site.get("line")
            sites.append({**site, "context": _source_window(files, path, line),
                          "javadoc": _javadoc_before(files, path, line)})
        item = {
            "kind": "call_v2", "name": full or str(call.get("name") or ""),
            "bare_name": str(call.get("name") or ""), "method_full_name": full,
            "signature": str(call.get("signature") or ""),
            "return_type": str(call.get("return_type") or ""),
            "resolved": bool(call.get("resolved")), "external": True,
            "n": int(call.get("occurrences") or 0), "sites": sites,
        }
        items.append(item)
    for method in cand.get("internal_methods", []):
        full = str(method.get("method_full_name") or "")
        for param in method.get("parameters") or []:
            idx = int(param.get("index") or 0)
            if idx < 1:
                continue
            path, line = str(method.get("file") or ""), method.get("line")
            items.append({
                "kind": "internal_method_parameter", "name": f"{full}#arg:{idx}",
                "method_full_name": full, "signature": str(method.get("signature") or ""),
                "parameter": param, "endpoint": f"arg:{idx}", "resolved": bool(full),
                "external": False, "n": 1, "visibility": method.get("visibility") or [],
                "annotations": method.get("annotations") or [],
                "context": _source_window(files, path, line),
                "javadoc": _javadoc_before(files, path, line),
            })
    for i, item in enumerate(items):
        item["id"] = i
    return items


def fmt_item_v2(item: dict) -> str:
    payload = {k: v for k, v in item.items() if k not in {"name", "n"}}
    payload["occurrences"] = item.get("n", 0)
    payload["required_exact_pattern"] = _exact_pattern(str(item.get("method_full_name") or ""))
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _extract_json_array(text: str) -> list | None:
    txt = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    if txt.startswith("```"):
        txt = re.sub(r"^```[a-z]*\n", "", txt)
        txt = re.sub(r"\n```$", "", txt)
    lb, rb = txt.find("["), txt.rfind("]")
    if lb == -1 or rb == -1 or rb <= lb:
        return None
    try:
        arr = json.loads(txt[lb:rb + 1])
        return arr if isinstance(arr, list) else None
    except Exception:  # noqa: BLE001
        return None


def label_items(items: list[dict], lang_label: str) -> list[dict]:
    """캐시미스 항목을 배치로 나눠 룰생성 모델을 호출, id로 매칭해 role 등을 items에 채운다."""
    by_id = {it["id"]: it for it in items}
    batches = [items[i:i + RULEGEN_BATCH] for i in range(0, len(items), RULEGEN_BATCH)]
    out: dict[int, dict] = {}

    def run_batch(bi_batch):
        bi, batch = bi_batch
        pending = list(batch)
        returned: dict[int, dict] = {}
        for attempt in range(3):
            body = "\n\n".join(fmt_item(it) for it in pending)
            user = RULEGEN_USER_TMPL.format(
                lang=lang_label, bi=bi + 1, bn=len(batches), items=body)
            try:
                text = call_rulegen(RULEGEN_SYSTEM, user, 200 * len(pending) * (attempt + 1))
            except Exception:  # noqa: BLE001
                continue
            arr = _extract_json_array(text)
            for obj in arr or []:
                if isinstance(obj, dict) and obj.get("id") in {it["id"] for it in pending}:
                    returned[obj["id"]] = obj
            pending = [it for it in pending if it["id"] not in returned]
            if not pending:
                break
        return list(returned.values())

    # Qwen3.8-Max API 대기시간이 전체 레포 지연을 지배하므로 독립 배치를 병렬 호출한다.
    with ThreadPoolExecutor(max_workers=min(LLM_MAX_WORKERS, max(1, len(batches)))) as ex:
        futs = {ex.submit(run_batch, x): x[0] for x in enumerate(batches)}
        for fut in as_completed(futs):
            for o in fut.result():
                if isinstance(o, dict) and "id" in o and o["id"] in by_id:
                    out[o["id"]] = o
    results = []
    for it in items:
        o = out.get(it["id"])
        if o is None:
            continue  # 파싱 실패/미판정 — role=none과 동일 취급(위음성 아님: 새 sink 후보일 뿐,
                      # taint_v4 손룰·§22 hand_rules가 커버하는 카테고리는 이미 별도로 잡힘)
        o["_candidate"] = {"name": it["name"], "kind": it["kind"], "n": it["n"]}
        results.append(o)
    return results


def label_items_v2(items: list[dict]) -> list[dict]:
    """Label exact Java candidates and attach immutable prompt/model provenance."""
    by_id = {item["id"]: item for item in items}
    batches = [items[i:i + RULEGEN_BATCH] for i in range(0, len(items), RULEGEN_BATCH)]
    cwes = json.dumps(CWE_DESCRIPTIONS, ensure_ascii=False, sort_keys=True)
    system_hash = hashlib.sha256(RULEGEN_V2_SYSTEM.encode()).hexdigest()

    def run_batch(pair: tuple[int, list[dict]]) -> list[dict]:
        bi, batch = pair
        body = "\n\n".join(fmt_item_v2(item) for item in batch)
        user = RULEGEN_V2_USER_TMPL.format(cwes=cwes, bi=bi + 1, bn=len(batches), items=body)
        prompt_hash = hashlib.sha256((RULEGEN_V2_SYSTEM + "\n" + user).encode()).hexdigest()
        for attempt in range(3):
            try:
                raw = call_rulegen(RULEGEN_V2_SYSTEM, user, 260 * len(batch) * (attempt + 1))
            except Exception:  # noqa: BLE001
                continue
            arr = _extract_json_array(raw)
            if arr is not None:
                return [{**obj, "_provenance": {
                    "schema": "scanops.rulegen.v2", "model": LLM_MODEL,
                    "system_prompt_sha256": system_hash, "prompt_sha256": prompt_hash,
                    "batch": bi,
                }} for obj in arr if isinstance(obj, dict)]
        return []

    returned: dict[int, dict] = {}
    with ThreadPoolExecutor(max_workers=min(LLM_MAX_WORKERS, max(1, len(batches)))) as ex:
        for outputs in ex.map(run_batch, enumerate(batches)):
            for obj in outputs:
                if obj.get("id") in by_id:
                    returned[obj["id"]] = obj
    results = []
    for item in items:
        obj = returned.get(item["id"])
        if obj is None:
            continue
        obj["_candidate"] = {
            "name": item["name"], "kind": item["kind"], "n": item["n"],
            "resolved": item.get("resolved", False),
            "method_full_name": item.get("method_full_name", ""),
        }
        results.append(obj)
    return results


# ── 검증/조립 (rebuild/graph_spec_to_joern.py 와 동일 규칙) ─────────────────

BAD_PATH = re.compile(r"[A-Za-z0-9_./\-]+\.(ts|tsx|js|jsx|mjs|cjs|py|java|scala|go|rb|php)\b")
BAD_PROG = re.compile(r"::program")

HAND_JSSRC = [
    ("sqli",       "CWE-89",  "name", "(?i)(query|execute|raw|prepare)"),
    ("cmdi",       "CWE-78",  "name", "(?i)(exec|execSync|spawn|spawnSync|execFile|fork)"),
    ("xss",        "CWE-79",  "name", "(?i)(innerHTML|outerHTML|write|send|render|insertAdjacentHTML|dangerouslySetInnerHTML)"),
    ("pathtraver", "CWE-22",  "name", "(?i)(readFile|readFileSync|writeFile|writeFileSync|createReadStream|unlink|sendFile)"),
    ("ssrf",       "CWE-918", "name", "(?i)(get|post|request|fetch|axios|got)"),
    ("deser",      "CWE-502", "name", "(?i)(parse|unserialize|deserialize)"),
    ("codei",      "CWE-94",  "name", "(?i)(eval|Function|runInNewContext|runInThisContext)"),
]
HAND_SRC = ("name", "(?i)(getParameter|getHeader|getQueryString|getInputStream|getCookies|"
                    "input|raw_input|request|argv|getenv|environ)")


def hand_rules(frontend: str = "JSSRC") -> list[dict]:
    if frontend != "JSSRC":
        return []
    out = [{"role": "sink", "cat": c, "cwe": w, "match": f, "pattern": p,
            "confidence": "hand", "why": "taint_v4.sc JSSRC hand rule", "_src": "hand"}
           for c, w, f, p in HAND_JSSRC]
    out.append({"role": "source", "match": HAND_SRC[0], "pattern": HAND_SRC[1],
                "confidence": "hand", "why": "taint_v4.sc srcCalls", "_src": "hand"})
    out.append({"role": "sink", "cat": "proto", "cwe": "CWE-1321",
                "match": "dynamic_index", "pattern": "",
                "confidence": "hand", "why": "동적 키 프로퍼티 대입 — 프로토타입 오염 sink 패턴",
                "_src": "hand"})
    return out


JAVA_BASE_SPEC_PATH = Path(__file__).with_name("specs") / "java_base.tsv"
JAVA_SANITIZER_SPEC_PATH = Path(__file__).with_name("specs") / "java_sanitizers.tsv"


def base_spec_text(frontend: str) -> str:
    """검증된 Java 기본 룰과 동적 Qwen 룰을 제품에서 함께 사용한다."""
    if frontend == "JAVASRC":
        return JAVA_BASE_SPEC_PATH.read_text()
    return to_tsv(hand_rules(frontend))


def sanitizer_spec_text(frontend: str) -> str:
    if frontend == "JAVASRC":
        return JAVA_SANITIZER_SPEC_PATH.read_text()
    return ""


def compose_spec_text(frontend: str, dynamic_rules: list[dict]) -> str:
    """Only benchmark-promoted deployments may let repository-generated rules affect verdicts."""
    base = base_spec_text(frontend).rstrip() + "\n"
    if DYNAMIC_RULE_MODE != "enforce":
        return base
    eligible = [r for r in dynamic_rules
                if r.get("_candidate", {}).get("kind") not in ("call_v2", "internal_method_parameter")
                or r.get("_enforce_eligible")]
    return base + to_tsv(eligible)


def language_context(language: str) -> tuple[str, str]:
    resolved = _resolve_lang(language or "")
    if not resolved:
        raise ValueError(f"unsupported language: {language}")
    frontend = resolved[1]
    labels = {"JAVASRC": "Java", "JSSRC": "TypeScript/JavaScript"}
    if frontend not in labels:
        raise ValueError(f"unsupported graph frontend: {frontend}")
    return frontend, labels[frontend]


def source_mode(frontend: str) -> str:
    """Java adds public data-carrier trust boundaries; legacy JS keeps its measured mode."""
    return "java" if frontend == "JAVASRC" else "params"


def repo_path_tokens_from_files(files: list[dict]) -> set[str]:
    """§9 반과적옵 필터용 — 레포 내부 모듈 경로 토큰을 파일 목록에서 직접 뽑는다
    (연구 스크립트는 디스크 staged_dir에서 뽑지만, 서빙은 files가 이미 메모리에 있다)."""
    toks: set[str] = set()
    for f in files:
        parts = Path(f.get("path") or "").parts
        parts = list(parts)
        if parts:
            parts[-1] = Path(parts[-1]).stem
        for i in range(len(parts)):
            seg = "/".join(parts[: i + 1])
            if "/" in seg:
                toks.add(seg)
    return toks


def validate(rules: list[dict], repo_toks: set[str]) -> list[dict]:
    good = []
    for o in rules:
        role = o.get("role")
        pat = (o.get("pattern") or "").strip()
        # `none`도 일반 API에 대한 유효한 판정이다. 캐시하지 않으면 같은 무관 API를 매
        # 스캔마다 Qwen에 다시 보내므로 검증 후 보존하고, to_tsv에서만 출력하지 않는다.
        if role not in ("sink", "source", "sanitizer", "propagator", "none"):
            continue
        if not pat:
            continue
        if BAD_PATH.search(pat) or BAD_PROG.search(pat):
            continue
        if any(t in pat for t in repo_toks):
            continue
        # 2026-09-05 6라운드 파일럿 §4: exists/exists_full 은 taint_spec.sc:249 에 처리 로직이
        # 이미 있었는데(오염 흐름 없이 콜 존재만으로 finding), 여기서 걸러버려서 CWE-338 처럼
        # "인자를 안 받는 sink"(Random.nextInt() 등)를 LLM 이 정확히 라벨링해도 룰로 못 옮기던
        # 구조적 갭이었다 — RULEGEN_SYSTEM 프롬프트에 이 두 값을 추가한 것과 짝을 맞춘다.
        # 2026-09-05 8라운드 §2: arg_literal/arg_literal_full 도 같은 이유로 추가 —
        # Cipher.getInstance("DES") 처럼 "어느 리터럴 인자가 오느냐"에 따라서만 위험한
        # sink(CWE-327 등)를 LLM 이 정확히 판단해도(6/7라운드 실측: role=none 으로 정직하게
        # 넘기고 있었다) 룰로 못 옮기던 두 번째 구조적 갭.
        if o.get("match") not in ("name", "full", "code", "assign_field", "internal_parameter",
                                   "exists", "exists_full",
                                   "arg_literal", "arg_literal_full",
                                   "arg_count", "arg_count_full"):
            continue
        if o.get("match") == "assign_field" and (o.get("_candidate") or {}).get("kind") != "assign":
            continue
        if role == "sink":
            cat = o.get("cat")
            if cat not in CATEGORY_CWES:
                continue
            cwe = str(o.get("cwe") or "").upper()
            if cwe and not cwe.startswith("CWE-"):
                cwe = f"CWE-{cwe}"
            if not cwe:
                allowed = CATEGORY_CWES[cat]
                if len(allowed) != 1:
                    continue
                cwe = next(iter(allowed))
            if cwe not in CATEGORY_CWES[cat]:
                continue
            o["cwe"] = cwe
        try:
            re.compile(pat)
        except re.error:
            continue
        if o.get("match") in ("arg_literal", "arg_literal_full"):
            arg_pat = (o.get("arg_pattern") or "").strip()
            if not arg_pat:
                continue
            if BAD_PATH.search(arg_pat) or BAD_PROG.search(arg_pat) or any(t in arg_pat for t in repo_toks):
                continue
            try:
                re.compile(arg_pat)
            except re.error:
                continue
        if o.get("match") in ("arg_count", "arg_count_full"):
            try:
                n_args = int(o.get("arg_count"))
            except (TypeError, ValueError):
                continue
            if n_args < 1:
                continue
            o["arg_count"] = n_args
        cand = o.get("_candidate") or {}
        if cand.get("kind") in ("call_v2", "internal_method_parameter"):
            endpoint = str(o.get("endpoint") or "")
            allowed_endpoints = {"return", "receiver", "call"}
            endpoint_ok = endpoint in allowed_endpoints or bool(re.fullmatch(r"arg:[1-9][0-9]*", endpoint))
            if not endpoint_ok:
                continue
            full = str(cand.get("method_full_name") or "")
            exact = _exact_pattern(full) if full else ""
            if o.get("match") == "internal_parameter":
                exact_match = cand.get("kind") == "internal_method_parameter" and pat == exact
            else:
                exact_match = o.get("match") == "full" and pat == exact
            o["rule_id"] = o.get("rule_id") or (
                "qwen38." + hashlib.sha256(
                    f"{role}|{o.get('cwe','')}|{pat}|{endpoint}".encode()).hexdigest()[:16]
            )
            o["_enforce_eligible"] = bool(
                cand.get("resolved") and exact_match and
                str(o.get("confidence") or "").lower() == "high" and
                role in ("sink", "source", "sanitizer", "propagator")
            )
        good.append(o)
    return good


def apply_cache_override(rules: list[dict], cache: dict, frontend: str = "JSSRC") -> list[dict]:
    """§21-1: 캐시가 항상 최종 근거. role=none으로 사람이 교정한 항목은 여기서 제외되고,
    캐시에 있는데 이번 LLM이 다르게 답했어도 캐시가 이긴다."""
    by_key: dict[str, dict] = {}
    for o in rules:
        cand = o.get("_candidate")
        if cand:
            by_key[cache_key(cand["kind"], cand["name"], frontend)] = o
    out = list(rules)
    for k, entry in cache.items():
        if entry.get("role") == "none":
            out = [o for o in out if not (o.get("_candidate") and
                   cache_key(o["_candidate"]["kind"], o["_candidate"]["name"], frontend) == k)]
            continue
        if k in by_key:
            by_key[k].update({kk: entry[kk] for kk in
                              ("role", "cat", "cwe", "match", "pattern", "arg_pattern", "arg_count",
                               "endpoint", "applies_to", "propagation", "rule_id",
                               "_provenance", "_enforce_eligible")
                              if kk in entry})
    return out


def to_tsv(rules: list[dict], cwe_hint: str | None = None) -> str:
    """cwe_hint: 2026-09-05 8라운드 §1 — CATS 는 (카테고리 -> CWE 1개) 고정 매핑이라
    여러 Juliet CWE 가 카테고리 하나를 공유하면(예: weakcrypto 는 CWE-321/327/328/338/
    759/760 전부가 씀, pathtraver 는 CWE-22/23/36 이 공유) 항상 CATS 의 대표 CWE 로만
    찍혀서 나머지는 findings.cwe 가 채점 대상 CWE 와 안 맞아 전부 미스로 잡혔다(7라운드
    파일럿에서 CWE-338/23 실측으로 확인, PHASE1-8_ABLATION_PILOT_R2_RESULTS.md §2/§4).
    이 파라미터를 주면 그 호출에서 만드는 sink 행 중 **cat 이 CWE_HINT_ELIGIBLE_CATS 에
    있는 것만** CATS 대신 이 값으로 덮어쓴다 — 호출자가 "이 배치는 전부 CWE-338 컨텍스트에서
    뽑은 후보다" 같은 걸 이미 알 때(벤치마크처럼 CWE 디렉터리 단위로 후보를 뽑는 경우)
    쓰라고 만든 것이다.
    **기본값 None 이면 예전과 100% 동일하게 CATS[cat] 을 쓴다** — 프로덕션(analyze_repo,
    레포 전체를 한 번에 스캔해서 어느 특정 CWE 컨텍스트인지 모름)은 이 인자를 안 넘기므로
    동작이 전혀 안 바뀐다(회귀 없음, 아래 호출부 참고).
    2026-09-05 9라운드 §1: 8라운드엔 cwe_hint 가 있으면 그 배치의 **모든** sink 에 무조건
    적용했다 — 한 호출 안에 우연히 다른(원래도 명확한) 카테고리(예: CWE-23 디렉터리에서
    뽑혔는데 ssrf/sqli 로 정확히 라벨링된 후보)가 섞이면 그 무관한 후보까지 cwe_hint 로
    덮어써서 FP 가 늘었다(CWE-23 실측: FP 0→4, F1 0.800→0.571,
    PHASE1-8_ABLATION_PILOT_R3_RESULTS.md §1/§4). 이번 라운드부터 **cat 이 알려진 다대다
    카테고리 집합에 있을 때만** cwe_hint 로 덮어쓰고, 그 외(sqli/cmdi 등 원래도 CATS[cat]
    하나로 명확한 카테고리)는 cwe_hint 를 무시하고 CATS[cat] 그대로 쓴다 — 그러면 그 배치에
    실수로 섞인 무관한 카테고리는 자기 CWE 로 남아 이 CWE 채점에서 자연히 빠진다(예전
    별칭 스크립트가 하던 일과 동일한 효과)."""
    lines = []
    for o in rules:
        if o["role"] == "sink":
            cat = o["cat"]
            if cwe_hint and cat in CWE_HINT_ELIGIBLE_CATS:
                cwe = cwe_hint
            else:
                cwe = o.get("cwe")
                if cwe not in CATEGORY_CWES.get(cat, set()):
                    allowed = CATEGORY_CWES.get(cat, set())
                    if len(allowed) != 1:
                        continue
                    cwe = next(iter(allowed))
            row = f"sink\t{o['cat']}\t{cwe}\t{o['match']}\t{o['pattern']}"
            # 2026-09-05 8라운드 §2: arg_literal(_full) 은 taint_spec.sc 가 6번째 열(argRe)을
            # 요구한다(taint_spec.sc:102 근처 `ln.split("\t", 6)` + `p(5)`). 이 필드가 없으면
            # 그냥 5열짜리로 나가 taint_spec.sc 가 argRe="" 로 받아 인자 조건 없이(사실상
            # 항상 매칭 안 함으로) 처리된다 — 그래서 반드시 채워야 한다.
            if o.get("match") in ("arg_literal", "arg_literal_full"):
                row += f"\t{o.get('arg_pattern', '')}"
            elif o.get("match") in ("arg_count", "arg_count_full"):
                row += f"\t{o.get('arg_count', '')}"
            elif o.get("endpoint"):
                row += "\t"
            if o.get("endpoint"):
                row += f"\t{o['endpoint']}\t{o.get('rule_id', '')}"
            lines.append(row)
        elif o["role"] == "source":
            row = f"source\t-\t-\t{o['match']}\t{o['pattern']}"
            if o.get("endpoint"):
                row += f"\t\t{o['endpoint']}\t{o.get('rule_id', '')}"
            lines.append(row)
    return "\n".join(lines) + "\n"


def to_sanitizer_tsv(rules: list[dict]) -> str:
    """Experimental v2 sanitizer arm; never enabled by the default product path."""
    lines = []
    for rule in rules:
        if rule.get("role") != "sanitizer" or not rule.get("_enforce_eligible"):
            continue
        applies = [x for x in rule.get("applies_to") or [] if x in CATEGORY_CWES]
        if applies:
            lines.append(f"dynamic.{rule.get('rule_id','unknown')}\t{','.join(applies)}\t{rule['pattern']}")
    return "\n".join(lines) + ("\n" if lines else "")


def to_propagation_tsv(rules: list[dict]) -> str:
    """Experimental exact-FQN propagation arm; malformed endpoint pairs are ignored."""
    lines = []
    for rule in rules:
        if rule.get("role") != "propagator" or not rule.get("_candidate", {}).get("resolved"):
            continue
        pairs = []
        for flow in rule.get("propagation") or []:
            src, dst = flow.get("from"), flow.get("to")
            if (src == "return" or isinstance(src, int)) and (dst == "return" or isinstance(dst, int)):
                pairs.append(f"{src},{dst}")
        if pairs and rule.get("match") == "full" and rule.get("pattern"):
            lines.append(f"{rule['pattern']}\t{';'.join(pairs)}")
    return "\n".join(lines) + ("\n" if lines else "")


# ── 오탐필터 (rebuild/graph_spec_critic_r3.py 와 동일 판정 규칙) ────────────

CTX = 6

CRITIC_SYSTEM = """You are auditing candidate taint-flow findings produced by a static analyser (Joern) on a real codebase.

For each finding you get: the vulnerability category and CWE, the flow the analyser found (source node -> intermediate nodes -> sink node, with file and line for each), and the source code around the sink and the source.

Decide whether the finding is a REAL vulnerability AT THE SINK LINE SHOWN.

Judge it as a security reviewer would:
- Is the data reaching the sink actually attacker-controlled? A hardcoded literal, a config constant, an internal enum, or a value the analyser merely passed through is not.
- Is the sink genuinely dangerous for that CWE at this call site?
- Is there neutralisation on the path (parameterised query, encoding, allow-list, type coercion, escaping)?
- Judge only what the shown code supports.

Use THREE verdicts. Do not collapse them:
  "TRUE"      — the evidence shown supports a real vulnerability at this sink line.
  "FALSE"     — the evidence shown positively rules it out (you can point at the line that rules it out).
  "UNCERTAIN" — you cannot tell from the shown code. Missing context, unresolved call, ambiguous data origin.

UNCERTAIN is a first-class answer, not a soft FALSE. Use it whenever you would otherwise guess.
Only answer FALSE when you can name the specific line that makes it safe.

Answer with ONE JSON array, no prose, no markdown fence. One object per finding, same order:
{"id": <int, echo the input id>,
 "verdict": "TRUE" | "FALSE" | "UNCERTAIN",
 "confidence": "high" | "med" | "low",
 "false_component": "source" | "sink" | "path" | "sanitizer" | "none",
 "false_rule_id": "<rule id when a reusable endpoint rule is wrong, otherwise empty>",
 "reusable_endpoint_rejection": <boolean>,
 "basis_line": <int — the line number your verdict rests on; REQUIRED when verdict is FALSE>,
 "reason": "<max 25 words>"}"""

CRITIC_USER_TMPL = """Repository language: {lang}
Judge each finding below.

{items}

Return the JSON array now."""


def _snippet_from_content(content: str, line: int | None, ctx: int = CTX) -> str:
    if not content or line is None or line < 1:
        return ""
    lines = content.splitlines()
    a, b = max(0, line - 1 - ctx), min(len(lines), line + ctx)
    return "\n".join(f"{i+1}: {lines[i]}" for i in range(a, b))


def _representative_path(path: list[dict], limit: int = 10) -> list[dict]:
    """Keep both endpoints and evenly sample long paths without front-only truncation."""
    if len(path) <= limit:
        return path
    indexes = {0, len(path) - 1}
    for i in range(limit):
        indexes.add(round(i * (len(path) - 1) / (limit - 1)))
    # If rounding collapsed indexes, prefer call-looking nodes for the remaining slots.
    for i, step in enumerate(path):
        if len(indexes) >= limit:
            break
        code = str(step.get("code") or "")
        if "(" in code and ")" in code:
            indexes.add(i)
    return [path[i] for i in sorted(indexes)[:limit - 1]] + [path[-1]]


def _fmt_finding(f: dict, content_by_path: dict[str, str]) -> str:
    path = f.get("path") or []
    steps = [{"role": s["role"], "file": s.get("file", ""), "line": s.get("line"),
              "code": (s.get("code") or "")[:150]} for s in _representative_path(path)]
    obj = {"id": f["_uid"], "category": f["category"], "cwe": f["cwe"],
           "cwe_description": CWE_DESCRIPTIONS.get(f["cwe"], ""),
           "sink": {"file": f["file"], "line": f.get("line"), "code": (f.get("sink") or "")[:200]},
           "source": {"file": f.get("source_file", ""), "line": f.get("source_line"),
                      "code": (f.get("source") or "")[:200],
                      "kind": f.get("source_kind", "unknown")},
           "flow": steps,
           "rule": {"id": f.get("rule_id", ""), "pattern": f.get("rule_pattern", ""),
                    "match": f.get("rule_field", ""), "endpoint": f.get("rule_endpoint", "")},
           "sanitizer_hits": [h.get("pattern") for h in (f.get("sanitizer_hits") or [])][:4],
           "duplicate_flows_at_same_location": f["_dup_count"]}
    out = [json.dumps(obj, ensure_ascii=False)]
    sc = _snippet_from_content(content_by_path.get(f["file"], ""), f.get("line"))
    if sc:
        out.append(f"SINK CONTEXT ({f['file']}):\n{sc}")
    sf, sl = f.get("source_file"), f.get("source_line")
    if sf and (sf != f["file"] or sl != f.get("line")):
        ssc = _snippet_from_content(content_by_path.get(sf, ""), sl)
        if ssc:
            out.append(f"SOURCE CONTEXT ({sf}):\n{ssc}")
    return "\n".join(out)


def _dedupe(findings: list[dict]) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for f in findings:
        k = (f["file"], f.get("line"), f["category"])
        g = groups.setdefault(k, {"rep": f, "n": 0})
        g["n"] += 1
    uniq = []
    for i, (k, g) in enumerate(sorted(groups.items(), key=lambda kv: (str(kv[0][0]), kv[0][1] or 0, kv[0][2]))):
        r = dict(g["rep"])
        r["_dup_count"] = g["n"]
        r["_uid"] = i
        uniq.append(r)
    return uniq


def _evidence_ok(f: dict, rendered: str) -> bool:
    """§12-4-1 — SINK CONTEXT의 중심 라인·파일이 finding과 일치하는지만 본다
    (rebuild/graph_spec_evidence_audit_r2.validate_evidence의 핵심 불변식)."""
    try:
        obj = json.loads(rendered.split("\n", 1)[0])
    except Exception:  # noqa: BLE001
        return False
    if obj["sink"]["file"] != f["file"] or obj["sink"]["line"] != f.get("line"):
        return False
    return True


def _critic_false_is_grounded(finding: dict, verdict: dict) -> bool:
    """Only allow a FALSE to suppress when its cited line was actually shown to the model."""
    if verdict.get("verdict") != "FALSE":
        return False
    if str(verdict.get("confidence", "")).lower() != CRITIC_FALSE_CONFIDENCE:
        return False
    try:
        basis = int(verdict["basis_line"])
    except (KeyError, TypeError, ValueError):
        return False
    shown = set()
    for line in (finding.get("line"), finding.get("source_line")):
        if isinstance(line, int) and line > 0:
            shown.update(range(max(1, line - CTX), line + CTX + 1))
    return basis in shown and bool(str(verdict.get("reason") or "").strip())


def review_findings(findings: list[dict], content_by_path: dict[str, str],
                    lang_label: str, enabled: bool | None = None) -> tuple[list[dict], dict]:
    """Review findings and return both kept findings and a reproducible critic audit."""
    critic_enabled = CRITIC_ENABLED if enabled is None else enabled
    if not findings:
        return [], {"enabled": critic_enabled, "input": 0, "kept": 0, "removed": 0,
                    "verdicts": [], "raw_batches": []}
    uniq = _dedupe([f for f in findings if not f.get("sanitized")])
    if not critic_enabled:
        return uniq, {"enabled": False, "input": len(uniq), "kept": len(uniq),
                      "removed": 0, "verdicts": [], "raw_batches": []}
    sendable, quarantined_uids = [], set()
    for f in uniq:
        rendered = _fmt_finding(f, content_by_path)
        if _evidence_ok(f, rendered):
            sendable.append(f)
        else:
            quarantined_uids.add(f["_uid"])   # evidence 불일치 — FALSE 아님, 그대로 살린다

    verdicts: dict[int, dict] = {}
    raw_batches: list[dict] = []
    batches = [sendable[i:i + CRITIC_BATCH] for i in range(0, len(sendable), CRITIC_BATCH)]
    def run_batch(batch):
        body = "\n\n".join(_fmt_finding(f, content_by_path) for f in batch)
        user = CRITIC_USER_TMPL.format(lang=lang_label, items=body)
        for attempt in range(2):   # 프로덕션은 연구용보다 재시도 줄임(레이턴시 예산)
            try:
                text = call_rulegen(CRITIC_SYSTEM, user, 250 * len(batch) * (attempt + 1))
            except Exception:  # noqa: BLE001
                continue
            arr = _extract_json_array(text)
            if arr:
                return arr, text
        return [], ""

    with ThreadPoolExecutor(max_workers=min(LLM_MAX_WORKERS, max(1, len(batches)))) as ex:
        for batch_index, (arr, raw) in enumerate(ex.map(run_batch, batches)):
            raw_batches.append({"batch": batch_index,
                                "ids": [f["_uid"] for f in batches[batch_index]],
                                "raw": raw})
            for o in arr:
                if isinstance(o, dict) and "id" in o:
                    verdicts[o["id"]] = o

    keep = []
    audit_verdicts = []
    for f in uniq:
        if f["_uid"] in quarantined_uids:
            f["_critic"] = {"verdict": "UNJUDGED", "reason": "evidence mismatch",
                              "suppressed": False}
            keep.append(f)
            audit_verdicts.append({"id": f["_uid"], **f["_critic"]})
            continue
        v = dict(verdicts.get(f["_uid"]) or {})
        grounded_false = _critic_false_is_grounded(f, v)
        if v.get("verdict") == "FALSE" and not grounded_false:
            v["original_verdict"] = "FALSE"
            v["verdict"] = "UNCERTAIN"
            v["validation_note"] = "FALSE lacked a shown high-confidence basis line"
        v["suppressed"] = grounded_false
        f["_critic"] = v or {"verdict": "UNJUDGED", "suppressed": False}
        audit_verdicts.append({"id": f["_uid"], **f["_critic"]})
        if grounded_false:
            continue   # 확신 있는 안전 판정만 제거
        keep.append(f)   # TRUE / UNCERTAIN / unjudged(파싱실패, v is None) 전부 유지
    return keep, {"enabled": True, "input": len(uniq), "kept": len(keep),
                  "removed": len(uniq) - len(keep),
                  "evidence_mismatch_ids": sorted(quarantined_uids),
                  "verdicts": audit_verdicts, "raw_batches": raw_batches}


def filter_findings(findings: list[dict], content_by_path: dict[str, str],
                    lang_label: str, enabled: bool | None = None) -> list[dict]:
    """§23 failsafe: only evidence-grounded high-confidence FALSE is removed."""
    return review_findings(findings, content_by_path, lang_label, enabled=enabled)[0]


# ── 오케스트레이션 ───────────────────────────────────────────────────────────

def analyze_repo(files: list[dict], language: str, repo_tag: str = "prod",
                 strict: bool = False) -> list[dict]:
    """files = [{"path","content"}] (한 언어의 레포 파일). 반환: findings(line 단위)."""
    if not ENABLED or not is_supported_lang(language) or not files:
        if strict and files and is_supported_lang(language):
            raise RuntimeError("graph-spec engine is disabled")
        return []
    frontend, lang_label = language_context(language)
    joern_ready = bool(JOERN_HTTP_URL) or bool(RUNPOD_API_KEY and JOERN_ENDPOINT_ID)
    if not joern_ready:
        if strict:
            raise RuntimeError("Java CPG runtime is not ready: configure a Joern endpoint")
        return []

    qwen_ready = qwen_runtime_ready()
    rulegen_effective = RULEGEN_ENABLED and qwen_ready
    critic_effective = CRITIC_ENABLED and qwen_ready
    if strict and CRITIC_ENABLED and not qwen_ready:
        raise RuntimeError(
            "graph-spec critic is enabled but Qwen3.8-Max runtime is not ready: "
            "configure DASHSCOPE_API_KEY and GRAPH_SPEC_LLM_MODEL=qwen3.8-max"
        )
    if strict and DYNAMIC_RULE_MODE == "enforce" and RULEGEN_ENABLED and not qwen_ready:
        raise RuntimeError(
            "dynamic rule enforcement requested live rule generation, but Qwen3.8-Max "
            "runtime is not ready; disable GRAPH_SPEC_RULEGEN_ENABLED for cache-only enforce"
        )

    # Candidate extraction is unnecessary for the fixed shadow/offline path. It is used
    # only to generate proposals, or to match an existing cache in explicit enforce mode.
    dynamic_rules: list[dict] = []
    need_candidates = rulegen_effective or DYNAMIC_RULE_MODE == "enforce"
    if need_candidates:
        try:
            candidate_schema = "v2" if frontend == "JAVASRC" and RULEGEN_CONTEXT_VERSION == "v2" else "v1"
            cand_out = call_joern_repo(
                "candidates", language, files, candidate_schema=candidate_schema)
            cand = cand_out.get("data") or {}
            candidate_error = cand.get("error") or ("timeout" if cand_out.get("timed_out") else "")
        except Exception as exc:  # noqa: BLE001 - optional enrichment must fail open
            if strict:
                raise RuntimeError(f"candidate extraction failed: {exc}") from exc
            cand = {}
        else:
            if candidate_error:
                if strict:
                    raise RuntimeError(f"candidate extraction failed: {candidate_error}")
                # Dynamic discovery must never prevent the fixed rules from reaching taint.
                cand = {}

        if cand:
            use_v2 = frontend == "JAVASRC" and RULEGEN_CONTEXT_VERSION == "v2"
            items = build_items_v2(cand, files) if use_v2 else build_items(cand, frontend, files)
            api_cache = load_api_cache()
            cached_items: list[tuple[dict, dict]] = []
            fresh_items = []
            for it in items:
                entry = _cache_lookup(api_cache, it, frontend)
                if entry is None:
                    fresh_items.append(it)
                else:
                    cached_items.append((it, entry))
            if MAX_FRESH_ITEMS > 0 and len(fresh_items) > MAX_FRESH_ITEMS:
                # Explicit operator override only. Accuracy-first default is unlimited (0).
                fresh_items = fresh_items[:MAX_FRESH_ITEMS]

            cached_rules = [
                {**entry, "_candidate": {
                    "name": it["name"], "kind": it["kind"], "n": it["n"],
                    "resolved": it.get("resolved", False),
                    "method_full_name": it.get("method_full_name", ""),
                }} for it, entry in cached_items
            ]
            labeled = ((label_items_v2(fresh_items) if use_v2 else label_items(fresh_items, lang_label))
                       if rulegen_effective and fresh_items else [])
            good = validate(labeled, repo_path_tokens_from_files(files))
            if rulegen_effective:
                update_api_cache(good, repo_tag, frontend)
            dynamic_rules = cached_rules + good

    # G3 dynamic arm preserved recall but increased active alerts 78→116 and strict FP 69→107.
    # Keep Qwen3.8 proposals/cache in shadow by default; enforcement requires an explicit,
    # benchmark-approved deployment setting.
    spec_text = compose_spec_text(frontend, dynamic_rules)

    dynamic_san = to_sanitizer_tsv(dynamic_rules) if DYNAMIC_SANITIZER_ENABLED else ""
    dynamic_prop = to_propagation_tsv(dynamic_rules) if DYNAMIC_PROPAGATION_ENABLED else ""
    taint_out = call_joern_repo(
        "taint", language, files, spec_text=spec_text,
        san_text=sanitizer_spec_text(frontend) + dynamic_san,
        prop_text=dynamic_prop,
        src_mode=source_mode(frontend), arm="S2C"
    )
    taint_data = taint_out.get("data") or {}
    if taint_out.get("timed_out") or taint_data.get("error"):
        if strict:
            raise RuntimeError(f"taint analysis failed: {taint_data.get('error') or 'timeout'}")
        return []
    findings = taint_data.get("findings") or []
    if not findings:
        return []

    content_by_path = {f.get("path", ""): f.get("content", "") for f in files}
    return filter_findings(findings, content_by_path, lang_label, enabled=critic_effective)
