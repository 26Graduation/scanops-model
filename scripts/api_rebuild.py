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

from scanops.core.llm_client import chat as llm_chat, completion as llm_completion, use_runpod

META_ENABLED = os.getenv("SCANOPS_META", "on").lower() != "off"
RAG_REFS_ENABLED = bool(os.getenv("QDRANT_URL", ""))

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


def _detect(language: str, code: str) -> dict:
    """모델 1회 호출 → 4줄 파싱. eval_gguf.py parse()와 동일 규칙 + REASON."""
    prompt = PROMPT_TMPL.format(language=language, code=code[:_MAX_CODE])
    raw = llm_completion(CHATML_TMPL.format(p=prompt),
                         {"num_predict": 200, "temperature": 0.0,
                          "stop": ["<|im_end|>"]})
    text = re.sub(r"<think>.*?(</think>|$)", "", raw, flags=re.S)
    vuln = sev = cvss = reason = ""
    for line in text.splitlines():
        s = line.strip()
        up = s.upper()
        if up.startswith("VULNERABILITY:") and not vuln:
            vuln = s.split(":", 1)[1].strip()
        elif up.startswith("SEVERITY:") and not sev:
            sev = s.split(":", 1)[1].strip().upper()
        elif up.startswith("CVSS:") and not cvss:
            cvss = s.split(":", 1)[1].strip()
        elif up.startswith("REASON:") and not reason:
            reason = s.split(":", 1)[1].strip()
    if not vuln:  # 파싱 실패 → 안전 판정 (백엔드 graceful 처리와 일관)
        return {"detected": False, "vulnerability": "NONE", "severity": "NONE",
                "cvss": None, "reason": "", "parse_fail": True}
    if vuln.upper().startswith("NONE"):
        return {"detected": False, "vulnerability": "NONE", "severity": "NONE",
                "cvss": None, "reason": ""}
    return {"detected": True, "vulnerability": vuln,
            "severity": sev or "UNKNOWN", "cvss": _cvss_float(cvss),
            "reason": "" if reason.upper() == "NONE" else reason}


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


def _analyze_one(language: str, code: str, file_path: Optional[str]) -> AnalyzeResponse:
    t0 = time.time()
    r = _detect(language, code)
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
        elapsed=round(time.time() - t0, 2),
    )


# ── 엔드포인트 ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "rebuild-1",
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
        try:
            r = _analyze_one(_lang_of(f.filename), f.content, f.filename)
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
        ))
    return PrScanResponse(repo=req.repo, pr_number=req.pr_number,
                          total_files=len(req.files),
                          vulnerable_count=len(findings),
                          findings=findings, elapsed=round(time.time() - t0, 2))
