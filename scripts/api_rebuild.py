"""ScanOps Rebuild API — 2026-07 재구축 Qwen3.5-9B 단일 모델, 백엔드 계약 전체 서빙
================================================================
모델 = 2026-07 전면 재구축(rebuild/) (CVEfixes 시간분할 test 1,197건에서
재현율 79.7% / 오탐률 15.7% / F1 80.5 — Claude Sonnet 5(F1 60.0)·Grok-4(54.1) 대비
실사용 지표 우위, rebuild/out/test_report.json).

설계(재구축 문제정의): **탐지는 파인튜닝 모델 단독**, RAG·그래프는 판정 후
설명층. 모델은 4줄 평문(VULNERABILITY/SEVERITY/CVSS/REASON)을 출력하고
이 서버가 백엔드 계약 JSON으로 조립한다.

api_v17.py 의 REST 계약(/analyze, /analyze/batch, /analyze/pr, /health)을 그대로
구현해 **Java 백엔드(ScanopsModelClient·GitHubAppWebhookController)는 무변경**.
GPU 호출 라우팅(scanops.core.llm_client):
  - RUNPOD_ENDPOINT_ID 설정 → RunPod serverless (워커: runpod/handler_rebuild.py)
  - 미설정 → 로컬 llama-server(:8080) / Ollama

실행:  uvicorn scripts.api_rebuild:app --host 0.0.0.0 --port 8100
환경변수:
  RUNPOD_ENDPOINT_ID / RUNPOD_API_KEY   (설정 시 GPU 호출을 RunPod로)
  LLAMA_SERVER_URL    (로컬 모드 llama-server 주소, 기본 http://localhost:8080)
  SCANOPS_API_KEY     (설정 시 X-API-Key 헤더 필요)
  SCANOPS_META=off    (탐지 시 한국어 메타 생성 끄기)
  QDRANT_URL          (설정 시 cve_references 3건 첨부 — 판정 미관여)
"""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field

from scanops.core.llm_client import (chat as llm_chat, completion as llm_completion,
                                     completion_logprobs, tokenize, use_runpod)
from scanops.core import hybrid as hybrid_mod
from scanops.core.logprob_score import PREFIX as SCORE_PREFIX, score_from_probs, verify_token_ids

META_ENABLED = os.getenv("SCANOPS_META", "on").lower() != "off"
RAG_REFS_ENABLED = bool(os.getenv("QDRANT_URL", ""))

# ── 하이브리드 (Phase 3) ────────────────────────────────────────────────────
# 정책은 Phase 2 의 사전 등록 게이트 판정을 그대로 주입한다.
# **실측 판정 = JOERN-NO-BETTER** (CleanVul_v2 층화 240건, Java/JS/Python 세 언어 전부.
# precision 0.5532, 95% CI [0.4468, 0.6489] — 0.5 를 포함 = 우연과 구별 불가.
# JOERN_HYBRID_REPORT.md §4-3) → 기본값을 그대로 둔다. Joern 은 판정에 관여하지 않고
# evidence 수집용으로만 붙는다.
HYBRID_POLICY = os.getenv("SCANOPS_HYBRID_POLICY", "JOERN-NO-BETTER")
JOERN_URL = os.getenv("SCANOPS_JOERN_URL", "")
# 연속 점수는 SIGNAL 정책에서만 필요하다. 매 요청 추가 호출이 붙으므로 기본 off.
SCORE_ENABLED = os.getenv("SCANOPS_SCORE", "").lower() in ("1", "on", "true") \
    or HYBRID_POLICY == "JOERN-AS-SIGNAL"
_TOKEN_CHECK: dict = {"checked": False, "ok": False, "note": "미확인"}

app = FastAPI(title="ScanOps Rebuild API", version="rebuild-1")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_API_KEY = os.getenv("SCANOPS_API_KEY", "")
_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def _require_api_key(key: Optional[str] = Security(_API_KEY_HEADER)) -> None:
    if _API_KEY and key != _API_KEY:
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


# ── 계약 모델 (api_v17.py 와 동일 스키마 — 백엔드 호환) ──────────────────────

class AnalyzeRequest(BaseModel):
    language: str
    code: str
    file_path: Optional[str] = None
    use_rag: bool = True                     # 하위호환 필드 (rebuild는 미사용)


class CveReference(BaseModel):
    cve_id: str
    severity: str
    base_score: float
    cwe_id: str
    description: str


class AnalyzeResponse(BaseModel):
    language: str
    file_path: Optional[str]
    detected: bool
    stage: int = 1                           # 단일 모델 — 항상 1
    vulnerability: str
    severity: str
    cvss_score: Optional[float] = None
    reason: str = ""                          # 모델 REASON 라인 (rebuild 추가, 영어 1줄)
    attack: str = ""                          # 한줄 공격 시나리오 (한국어, 메타 생성)
    fix: str = ""                             # 해결 방법 (한국어, 메타 생성)
    summary: str = ""                         # 한줄 정리 (한국어) — 실패 시 REASON 폴백
    ai_prompt: str = ""                       # 사용자가 외부 AI에 넘길 핸드오프 프롬프트
    cve_references: list[CveReference] = Field(default_factory=list)
    kg_risk_score: Optional[float] = None    # 하위호환 (rebuild 미사용)
    graph_evidence: list[dict] = Field(default_factory=list)
    suppressed_by_graph: bool = False
    votes: Optional[dict] = None             # {"model": bool}
    # ── 하이브리드 (Phase 3) ────────────────────────────────────────────────
    score: Optional[float] = None            # logP(" CWE") − logP(" NONE"). 미지원 시 None
    source: str = "llm"                      # llm | joern | llm+joern | graph
    evidence: Optional[list] = None          # Joern taint path 또는 graph reason
    status: str = "DONE"                     # PARTIAL(Joern 미도착) | DONE
    # Joern v4 근거(판정 미개입). advisory_only=True 로 표시된다 — REPORT_V4 §6
    joern_evidence: Optional[dict] = None
    # 파싱 재시도 여부(운영 관측용). True 면 1회 재시도 후의 결과다.
    parse_retried: bool = False
    elapsed: float


class BatchRequest(BaseModel):
    files: list[AnalyzeRequest]
    stop_on_first: bool = False


class BatchResponse(BaseModel):
    total: int
    detected_count: int
    results: list[AnalyzeResponse]
    elapsed: float


class PrFile(BaseModel):
    filename: str
    content: str
    patch: Optional[str] = None


class PrScanRequest(BaseModel):
    repo: str
    pr_number: int
    files: list[PrFile]


class PrFinding(BaseModel):
    filename: str
    detected: bool
    vulnerability: str
    severity: str
    cvss_score: Optional[float]
    reason: str = ""
    attack: str = ""
    fix: str = ""
    summary: str = ""
    ai_prompt: str = ""
    cve_references: list[CveReference] = Field(default_factory=list)
    kg_risk_score: Optional[float] = None
    graph_evidence: list[dict] = Field(default_factory=list)
    suppressed_by_graph: bool = False
    diff_line: Optional[int] = None
    # `[DIFF]` 마커로 표시한 변경 줄 수. 플래그 off 이거나 patch 가 없으면 None.
    diff_marked_lines: Optional[int] = None


class PrScanResponse(BaseModel):
    repo: str
    pr_number: int
    total_files: int
    vulnerable_count: int
    findings: list[PrFinding]
    elapsed: float


# ── 판정 (rebuild 학습 템플릿과 동일 — rebuild/build_dataset.py) ─────────────

PROMPT_TMPL = """Analyze the following {language} code for security vulnerabilities.

```{language}
{code}
```

Respond in exactly this format:
VULNERABILITY: <CWE-id (CWE name)> or NONE
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN> or NONE
CVSS: <score 0.0-10.0> or 0.0
REASON: <one-line explanation> or NONE"""

# 학습 completion이 "<|im_start|>assistant\n" 직후 VULNERABILITY로 시작하도록
# 학습됐으므로 같은 지점까지 수동 ChatML 래핑 (<think> 방지, eval_gguf.py와 동일).
CHATML_TMPL = "<|im_start|>user\n{p}<|im_end|>\n<|im_start|>assistant\n"

# 학습 데이터 코드 길이 상한(12,000자)에 맞춰 자름 — 초과분은 OOD.
_MAX_CODE = 12_000


# 4줄 서식 추출 — 응답 **어디에 있든** 잡는다.
# 기존은 줄 시작(startswith)에만 의존해서, 모델이 서론을 붙이거나 들여쓰기하면
# 통째로 파싱 실패했다(실측: 베이스 모델 경로에서 전부 NONE).
_RE_VULN = re.compile(r"VULNERABILITY:\s*(.+)", re.I)
_RE_SEV = re.compile(r"SEVERITY:\s*(.+)", re.I)
_RE_CVSS = re.compile(r"CVSS:\s*(.+)", re.I)
_RE_REASON = re.compile(r"REASON:\s*(.+)", re.I)

# 파싱 실패 시 재시도 예산. <think> 가 200 토큰을 다 먹는 경우가 실측됐다
# (FINAL_ARCHITECTURE_REPORT.md §6 — 베이스 모델이 사고만 하다 잘림).
_RETRY_NPREDICT = int(os.getenv("SCANOPS_RETRY_NPREDICT", "1500"))
# 응답이 <think> 로 시작하면 사고 모드다. 어댑터 경로는 이 서식을 내지 않으므로
# 이 프리필은 베이스 모델 경로에서만 발동한다.
_THINK_PREFILL = "<think>\n\n</think>\n\n"

_PARSE_STATS = {"total": 0, "retried": 0, "retry_ok": 0, "fail": 0}


def _parse4(raw: str) -> tuple[str, str, str, str]:
    text = re.sub(r"<think>.*?(</think>|$)", " ", raw, flags=re.S)
    def g(rx):
        m = rx.search(text)
        return m.group(1).strip() if m else ""
    return g(_RE_VULN), g(_RE_SEV).upper(), g(_RE_CVSS), g(_RE_REASON)


def _detect(language: str, code: str, prompt_code: Optional[str] = None) -> dict:
    """모델 호출 → 4줄 파싱. 실패 시 **1회만** 예산을 늘려 재시도한다.

    반환에 debug 필드(retried/parse_fail)를 실어 운영에서 재시도율을 볼 수 있게 한다.

    `prompt_code` 는 **LLM 프롬프트에만** 쓰는 대체 본문이다(PR 경로의 `[DIFF]` 마커).
    None 이면 `code` 를 그대로 쓴다 = 기존과 바이트 동일. graph/Joern/점수 경로는
    언제나 원본 `code` 를 본다 — 마커가 정적 분석 입력을 바꾸지 않게 하기 위해서다.
    """
    prompt = PROMPT_TMPL.format(
        language=language, code=(code if prompt_code is None else prompt_code)[:_MAX_CODE])
    _PARSE_STATS["total"] += 1

    raw = llm_completion(CHATML_TMPL.format(p=prompt),
                         {"num_predict": 200, "temperature": 0.0,
                          "stop": ["<|im_end|>"]})
    vuln, sev, cvss, reason = _parse4(raw)
    retried = False

    if not vuln:
        # 1회 재시도: 예산을 늘리고, 사고 모드로 보이면 빈 think 블록을 프리필해 억제한다.
        retried = True
        _PARSE_STATS["retried"] += 1
        prefill = _THINK_PREFILL if raw.lstrip().startswith("<think>") else ""
        raw2 = llm_completion(CHATML_TMPL.format(p=prompt) + prefill,
                              {"num_predict": _RETRY_NPREDICT, "temperature": 0.0,
                               "stop": ["<|im_end|>"]})
        vuln, sev, cvss, reason = _parse4(raw2)
        if vuln:
            _PARSE_STATS["retry_ok"] += 1

    if not vuln:  # 재시도 후에도 실패 → 안전 판정 (백엔드 graceful 처리와 일관)
        _PARSE_STATS["fail"] += 1
        print(f"[detect] PARSE_FAIL lang={language} retried={retried}", flush=True)
        return {"detected": False, "vulnerability": "NONE", "severity": "NONE",
                "cvss": None, "reason": "", "parse_fail": True, "retried": retried}
    if vuln.upper().startswith("NONE"):
        return {"detected": False, "vulnerability": "NONE", "severity": "NONE",
                "cvss": None, "reason": "", "retried": retried}
    return {"detected": True, "vulnerability": vuln,
            "severity": sev or "UNKNOWN", "cvss": _cvss_float(cvss),
            "reason": "" if reason.upper() == "NONE" else reason,
            "retried": retried}


# ═══════════════════════════════════════════════════════════════════════════
# v2 분기 (V2_RUN_SPEC.md rev.6 §11)
# ═══════════════════════════════════════════════════════════════════════════
# §11 은 v1 파일 동결을 원칙으로 하되, **이 파일만은 예외**로 "같은 파일 안에 v1/v2 분기를
# 나란히 두는 것"을 허용한다(완전 별도 파일로 쪼개면 서빙 스위칭 로직이 이원화되므로).
#
# 규칙:
#  · 위쪽 v1 경로(PROMPT_TMPL / CHATML_TMPL / _detect)는 **한 글자도 바꾸지 않았다.**
#    `rebuild/repo_bench_scan.py:_assert_prompt_parity()` 가 이 파일에서 그 두 문자열을
#    찾아 대조하므로, 건드리면 v1 벤치가 즉시 깨진다.
#  · v2 경로는 프롬프트·포맷·4096 예산·파서를 전부 `rebuild/prompt_v2.py` 에서 import 한다.
#    여기에 프롬프트 문자열을 다시 적지 않는다 — 그게 §11 단일 소스의 요점이다.
#
# 전환: 환경변수 `SCANOPS_MODEL_VERSION=v2` (기본값 v1 — 미설정 시 동작 무변화).

_V2_ENABLED = os.getenv("SCANOPS_MODEL_VERSION", "v1").lower() == "v2"
_V2_TOKENIZER_ID = os.getenv("V2_TOKENIZER", "unsloth/Qwen3.5-9B")
_v2_mod = None
_v2_tok = None


def _v2_load():
    """prompt_v2 와 토크나이저를 지연 로드한다 (v1 경로만 쓸 때 비용 0)."""
    global _v2_mod, _v2_tok
    if _v2_mod is None:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rebuild"))
        import prompt_v2 as _p
        from transformers import AutoTokenizer
        _v2_mod = _p
        _v2_tok = AutoTokenizer.from_pretrained(_V2_TOKENIZER_ID)
    return _v2_mod, _v2_tok


def _detect_v2(language: str, code: str, prompt_code: Optional[str] = None) -> dict:
    """v2 판정 — 파일 단위 입력(최대 4096-token context) + 5줄 출력(LINE 포함).

    v1 `_detect` 와 다른 점:
      · 코드를 12,000자로 자르지 않고 §8-2 절차(줄번호 부여 → 조립 → 실측 → 뒤에서 절단)를
        학습 데이터 구축·평가와 **같은 함수**로 적용한다.
      · 생성 프리필이 학습 텍스트 접두사와 바이트 동일하다
        (`<|im_start|>assistant\\n<think>\\n\\n</think>\\n\\n` 까지 포함 — build_generation_prompt()).
      · 출력에 `line` 이 실린다.
    """
    P, tok = _v2_load()
    src = code if prompt_code is None else prompt_code
    b = P.build_input_within_budget(src, language, tok, line=None)
    raw = llm_completion(
        P.build_generation_prompt(b["prompt"], tok),
        {"num_predict": P.COMPLETION_RESERVE_TOKENS, "temperature": 0.0,
         "stop": ["<|im_end|>"]})
    r = P.parse_output_v2(raw)
    base = {
        "model_version": "v2",
        "truncated": b["truncated"],
        "input_tokens": b["input_tokens"],
        "file_lines_total": b["file_lines_total"],
        "lines_kept": b["lines_kept"],
        "format_inconsistent": r["format_inconsistent"],
    }
    if r["label"] == "parse_fail":
        return {**base, "detected": False, "vulnerability": "NONE", "severity": "NONE",
                "cvss": None, "reason": "", "line": None, "parse_fail": True}
    if r["label"] == "safe":
        return {**base, "detected": False, "vulnerability": "NONE", "severity": "NONE",
                "cvss": None, "reason": "", "line": 0}
    return {**base, "detected": True, "vulnerability": r["cwe"],
            "severity": (r["severity"] or "UNKNOWN").upper(),
            "cvss": _cvss_float(r["cvss"]), "line": r["line"],
            "reason": "" if r["reason"].upper() == "NONE" else r["reason"]}


def detect(language: str, code: str, prompt_code: Optional[str] = None) -> dict:
    """서빙 진입점 — SCANOPS_MODEL_VERSION 에 따라 v1/v2 로 분기한다."""
    if _V2_ENABLED:
        return _detect_v2(language, code, prompt_code)
    return _detect(language, code, prompt_code)


# ── 헬퍼 (api_v17.py 와 동일) ────────────────────────────────────────────────

_EXT_LANG = {
    ".py": "Python", ".java": "Java", ".js": "Node.js / Express",
    ".jsx": "Node.js / Express", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".php": "PHP", ".rb": "Ruby", ".go": "Go", ".cs": "C#",
    ".c": "C", ".cpp": "C++", ".kt": "Kotlin", ".rs": "Rust",
}


def _lang_of(filename: str, default: str = "Python") -> str:
    for ext, lang in _EXT_LANG.items():
        if filename.endswith(ext):
            return lang
    return default


def _first_added_line(patch: Optional[str]) -> Optional[int]:
    """git patch 에서 첫 번째 추가(+) 라인의 새 파일 기준 라인 번호."""
    if not patch:
        return None
    new_ln = 0
    for line in patch.splitlines():
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)", line)
        if m:
            new_ln = int(m.group(1)) - 1
            continue
        if line.startswith("+") and not line.startswith("+++"):
            return new_ln + 1
        if not line.startswith("-"):
            new_ln += 1
    return None


# ── PR 경로 `[DIFF]` 마커 (기본 on, 되돌림은 환경변수 하나) ────────────────────
# 근거: rebuild/out/DIFF_AWARE_RESULTS.md — v1 그대로 쌍 판별 0.4600 → 0.6050
# (+0.1450 [+0.0650, +0.2225], 위치 상쇄 후). 단건 회귀 없음(내부 test 0.9101 동일,
# CyberNative +0.0176), 안전 판본 오탐률 0.065 불변.
# **사전등록 게이트는 통과하지 못했다**(`CB-PARTIAL`, 동점률 0.155 > 0.10).
# 그래서 이것은 게이트 통과가 아니라 **제품 판단**이고, 그 사실을 문서에 적는다.
# SCANOPS_PR_DIFF_MARKER=0 으로 끄면 프롬프트가 이전과 **바이트 동일**해진다.
PR_DIFF_MARKER = os.getenv("SCANOPS_PR_DIFF_MARKER", "1").lower() in ("1", "on", "true")


def _pr_marked_content(language: str, content: str,
                       patch: Optional[str]) -> tuple[Optional[str], Optional[int]]:
    """PR 프롬프트용 본문과 표시한 변경 줄 수.

    반환이 (None, None) 이면 호출측은 **원본 그대로** 쓴다 = 현행과 바이트 동일.
    변경 줄이 하나도 없으면(패치 없음·삭제만 있는 hunk) 마커를 넣지 않는다.
    """
    if not PR_DIFF_MARKER or not patch:
        return None, None
    try:
        from rebuild.pr_diff_marker import changed_lines_from_patch, mark_content
        changed = changed_lines_from_patch(patch)
        if not changed:
            return None, 0
        return mark_content(content, changed, language), len(changed)
    except Exception:  # noqa: BLE001 — 마커 실패가 스캔을 죽이지 않게
        return None, None


def _cvss_float(v) -> Optional[float]:
    try:
        f = float(str(v).strip())
        return f if 0.0 <= f <= 10.0 else None
    except (TypeError, ValueError):
        return None


def _gen_meta(language: str, code: str, vuln: str, reason: str) -> dict:
    """탐지된 취약점의 한국어 메타 생성. 같은 모델의 chat 경로 1회 호출.

    (QLoRA는 판정 서식 특화지만 베이스 능력을 보존 — chat 템플릿 경로로 호출하면
    일반 지시수행이 동작한다.) 실패해도 판정 결과엔 영향 없음(빈 문자열).
    """
    if not META_ENABLED:
        return {}
    prompt = (
        f'{language} 코드에서 "{vuln}" 취약점이 탐지되었습니다.\n'
        f"탐지 근거: {reason or 'N/A'}\n"
        f"```\n{code[:1200]}\n```\n"
        "아래 JSON 형식으로만 응답하세요. 다른 텍스트는 포함하지 마세요.\n"
        '{"summary":"한 줄 요약 (한국어)",'
        '"attack":"공격 시나리오 한 문장 (한국어)",'
        '"fix":"해결 방법, 가능하면 수정 코드 한 줄 포함 (한국어)"}'
    )
    try:
        # Qwen3.5는 chat 경로에서 <think>가 먼저 나와 토큰을 소모 → 넉넉히 잡아야
        # think 이후의 실제 JSON이 잘리지 않는다 (워커가 <think> 블록은 제거해 반환).
        # 1200으로는 한국어 메타 프롬프트에서 think가 예산을 다 먹는 경우가 실측됨 → 3000.
        raw = llm_chat("", [{"role": "user", "content": prompt}],
                       {"temperature": 0.2, "num_predict": 3000}, timeout=180)
        m = re.search(r"\{.*\}", raw, re.S)
        if not m:
            return {}
        import json as _json
        d = _json.loads(m.group(0))
        return {k: str(d.get(k) or "")[:500] for k in ("summary", "attack", "fix")}
    except Exception:  # noqa: BLE001
        return {}


def _handoff_prompt(language: str, code: str, vuln: str, severity: str,
                    cvss: Optional[float]) -> str:
    """사용자가 ChatGPT/Claude 등 외부 AI에 그대로 붙여넣을 핸드오프 프롬프트."""
    return (
        f"보안 스캐너(ScanOps)가 아래 {language} 코드에서 취약점을 탐지했습니다.\n"
        f"- 취약점: {vuln}\n- 심각도: {severity} (CVSS {cvss if cvss is not None else 'N/A'})\n\n"
        f"```\n{code[:2000]}\n```\n\n"
        "이 취약점이 실제로 악용 가능한지 검토하고, 안전한 수정 코드를 제시해주세요. "
        "수정 후에도 기존 기능이 동일하게 동작해야 합니다."
    )


def _cve_refs(language: str, code: str, vuln: str) -> list[CveReference]:
    """RAG 참조 CVE (QDRANT_URL 설정 시에만). 판정에는 관여하지 않음 — 참고자료 전용."""
    if not RAG_REFS_ENABLED:
        return []
    try:
        from scripts.benchmark_qwen_rag import search_cves
        hits = search_cves(f"{language} {vuln} {code[:300]}", top_k=3)
        return [CveReference(cve_id=h["cve_id"], severity=str(h["severity"]),
                             base_score=float(h["base_score"] or 0),
                             cwe_id=str(h["cwe_id"]), description=h["description"])
                for h in hits]
    except Exception:  # noqa: BLE001
        return []


def _score(language: str, code: str) -> Optional[float]:
    """연속 점수 — rebuild/score_logprob.py 와 동일 정의.

    서빙 토크나이저의 토큰 ID가 rebuild 기준값과 다르면 **자동 보정하지 않고 None** 을
    돌려준다 (점수 정의가 바뀌면 rebuild 의 AUC·τ 와 비교 불가 — 사양서 §3).
    """
    global _TOKEN_CHECK
    if not SCORE_ENABLED:
        return None
    if not _TOKEN_CHECK["checked"]:
        _TOKEN_CHECK = {**verify_token_ids(tokenize), "checked": True}
        print(f"[score] token check: {_TOKEN_CHECK}", flush=True)
    if not _TOKEN_CHECK.get("ok"):
        return None
    prompt = PROMPT_TMPL.format(language=language, code=code[:_MAX_CODE])
    try:
        probs = completion_logprobs(CHATML_TMPL.format(p=prompt) + SCORE_PREFIX)
        return score_from_probs(probs)
    except Exception:  # noqa: BLE001 — 점수는 부가 정보, 판정을 죽이지 않는다
        return None


def _joern(language: str, code: str, file_path: Optional[str]) -> Optional[dict]:
    """Joern 워커 동기 조회. 미설정/실패면 None → 하이브리드는 status=PARTIAL."""
    if not JOERN_URL:
        return None
    try:
        import requests
        r = requests.post(f"{JOERN_URL.rstrip('/')}/joern/analyze", json={
            "job_id": f"api_{int(time.time()*1000)}",
            "language": language,
            "files": [{"path": file_path or "snippet", "content": code}],
        }, timeout=int(os.getenv("SCANOPS_JOERN_TIMEOUT", "120")))
        r.raise_for_status()
        res = (r.json().get("results") or {})
        v = res.get(file_path or "snippet")
        if not v:
            return None
        # findings 각각이 path 리스트를 갖는다 → 평탄화해야 evidence.flow 가
        # [{line,code,role}, ...] 형태가 된다(중첩 리스트로 나가던 것을 교정).
        steps: list = []
        seen: set = set()
        for f in v.get("findings", []):
            for st in (f.get("path") or []):
                key = (st.get("line"), (st.get("code") or "").strip()) \
                    if isinstance(st, dict) else (None, str(st))
                if key in seen:
                    continue
                seen.add(key)
                steps.append(st)
        return {"verdict": v.get("verdict", "unknown"),
                "categories": v.get("categories", []),
                "sanitizer_hits": v.get("sanitizer_hits", []),
                "path": steps}
    except Exception:  # noqa: BLE001
        return None


def _analyze_one(language: str, code: str, file_path: Optional[str],
                 prompt_code: Optional[str] = None) -> AnalyzeResponse:
    t0 = time.time()
    r = _detect(language, code, prompt_code)
    r["score"] = _score(language, code)
    joern = _joern(language, code, file_path)
    agg = hybrid_mod.aggregate(r, joern, None, HYBRID_POLICY)
    r = {**r, "detected": agg["detected"]}
    if agg["detected"] and agg["source"] in ("joern", "graph") and r["vulnerability"] == "NONE":
        r["vulnerability"] = agg["vulnerability"]
        r["severity"] = agg["severity"]
        r["reason"] = agg["reason"]
    meta, handoff, refs = {}, "", []
    if r["detected"]:
        meta = _gen_meta(language, code, r["vulnerability"], r["reason"])
        handoff = _handoff_prompt(language, code, r["vulnerability"],
                                  r["severity"], r["cvss"])
        refs = _cve_refs(language, code, r["vulnerability"])
    return AnalyzeResponse(
        language=language, file_path=file_path,
        detected=r["detected"],
        vulnerability=r["vulnerability"],
        severity=r["severity"],
        cvss_score=r["cvss"],
        reason=r["reason"],
        attack=meta.get("attack", ""),
        fix=meta.get("fix", ""),
        summary=meta.get("summary", "") or r["reason"],
        ai_prompt=handoff,
        cve_references=refs,
        votes={"model": r["detected"]},
        score=agg.get("score"),
        source=agg.get("source", "llm"),
        evidence=agg.get("evidence") if isinstance(agg.get("evidence"), list) else
                 ([agg["evidence"]] if agg.get("evidence") else None),
        status=agg.get("status", "DONE"),
        joern_evidence=agg.get("joern_evidence"),
        parse_retried=bool(r.get("retried")),
        elapsed=round(time.time() - t0, 2),
    )


# ── 엔드포인트 ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "rebuild-1",
            "parse_stats": dict(_PARSE_STATS),
            "model": "scanops-rebuild-9b (Qwen3.5-9B QLoRA, CVEfixes F1 80.5)",
            "llm_backend": "runpod" if use_runpod() else "llama-local"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest, _=Security(_require_api_key)):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="empty code")
    try:
        return _analyze_one(req.language, req.code, req.file_path)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"model backend error: {e}")


@app.post("/analyze/batch", response_model=BatchResponse)
def analyze_batch(req: BatchRequest, _=Security(_require_api_key)):
    t0 = time.time()
    results: list[AnalyzeResponse] = []
    for f in req.files:
        if not f.code.strip():
            continue
        try:
            r = _analyze_one(f.language, f.code, f.file_path)
        except Exception:  # noqa: BLE001 — 한 파일 실패가 배치 전체를 죽이지 않게
            continue
        results.append(r)
        if req.stop_on_first and r.detected:
            break
    return BatchResponse(total=len(req.files),
                         detected_count=sum(1 for r in results if r.detected),
                         results=results, elapsed=round(time.time() - t0, 2))


@app.post("/analyze/pr", response_model=PrScanResponse)
def analyze_pr(req: PrScanRequest, _=Security(_require_api_key)):
    t0 = time.time()
    findings: list[PrFinding] = []
    for f in req.files:
        if not f.content.strip():
            continue
        lang = _lang_of(f.filename)
        prompt_code, marked = _pr_marked_content(lang, f.content, f.patch)
        try:
            r = _analyze_one(lang, f.content, f.filename, prompt_code=prompt_code)
        except Exception:  # noqa: BLE001
            continue
        if not r.detected:
            continue
        findings.append(PrFinding(
            filename=f.filename, detected=True,
            vulnerability=r.vulnerability, severity=r.severity,
            cvss_score=r.cvss_score, reason=r.reason,
            attack=r.attack, fix=r.fix, summary=r.summary,
            ai_prompt=r.ai_prompt, cve_references=r.cve_references,
            diff_line=_first_added_line(f.patch),
            diff_marked_lines=marked,
        ))
    return PrScanResponse(repo=req.repo, pr_number=req.pr_number,
                          total_files=len(req.files),
                          vulnerable_count=len(findings),
                          findings=findings, elapsed=round(time.time() - t0, 2))
