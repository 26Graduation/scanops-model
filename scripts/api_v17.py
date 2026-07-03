"""ScanOps V17 API — v13 ∨ v16.1 OR 앙상블, 백엔드 계약 전체 서빙
================================================================
V17 = v13(고재현율) ∨ v16.1(광커버리지) ∨ 코드그래프. 4벤치 평균 F1 62.1로
V15(59.9)·Grok(56.2) 능가 (reports/V16_RESULTS.md).

api_server.py 의 REST 계약(/analyze, /analyze/batch, /analyze/pr, /health)을 그대로
구현해 **Java 백엔드(ScanopsModelClient·GitHubAppWebhookController)는 무변경**.
GPU가 필요한 LLM 호출은 scanops.core.llm_client 가 라우팅:
  - RUNPOD_ENDPOINT_ID 설정 → RunPod serverless (이 서버 자체는 CPU 인스턴스면 충분)
  - 미설정 → 로컬 Ollama (기존 EC2/로컬 방식)

실행:  uvicorn scripts.api_v17:app --host 0.0.0.0 --port 8100
환경변수:
  SCANOPS_V13_MODEL   (기본 qwen2.5-coder-security-v13-7b:latest)
  SCANOPS_V14_MODEL   (기본 qwen2.5-coder-security-v16-1-7b:latest — V17의 2번 멤버)
  RUNPOD_ENDPOINT_ID / RUNPOD_API_KEY   (설정 시 GPU 호출을 RunPod로)
  SCANOPS_API_KEY     (설정 시 X-API-Key 헤더 필요)
"""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# V17: 앙상블 2번 멤버 기본값을 v16.1로 (env로 오버라이드 가능)
os.environ.setdefault("SCANOPS_V14_MODEL", "qwen2.5-coder-security-v16-1-7b:latest")

from fastapi import FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field

from scanops.core.ensemble import predict, V13_MODEL, V14_MODEL
from scanops.core.llm_client import chat as llm_chat, use_runpod

# 탐지 시 한국어 메타(한줄요약/공격/수정) 생성 — DAST(generateMeta)와 대칭.
# 파인튜닝 모델은 3줄 판정 특화라, 설명은 베이스 instruct 모델이 담당.
META_MODEL = os.getenv("SCANOPS_META_MODEL", "qwen2.5-coder:7b-instruct")
META_ENABLED = os.getenv("SCANOPS_META", "on").lower() != "off"
RAG_REFS_ENABLED = bool(os.getenv("QDRANT_URL", ""))

app = FastAPI(title="ScanOps V17 Ensemble API", version="17.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_API_KEY = os.getenv("SCANOPS_API_KEY", "")
_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def _require_api_key(key: Optional[str] = Security(_API_KEY_HEADER)) -> None:
    if _API_KEY and key != _API_KEY:
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


# ── 계약 모델 (api_server.py 와 동일 스키마 — 백엔드 호환) ────────────────────

class AnalyzeRequest(BaseModel):
    language: str
    code: str
    file_path: Optional[str] = None
    use_rag: bool = True                     # 하위호환 필드 (V17은 미사용)


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
    stage: int                               # 1=v13, 2=v16.1 보강, 3=graph 보강
    vulnerability: str
    severity: str
    cvss_score: Optional[float] = None
    attack: str = ""                          # 한줄 공격 시나리오 (한국어, 메타 생성)
    fix: str = ""                             # 해결 방법 (한국어, 메타 생성)
    summary: str = ""                         # 한줄 정리 (한국어) — DAST summary와 대칭
    ai_prompt: str = ""                       # 사용자가 외부 AI에 넘길 핸드오프 프롬프트
    cve_references: list[CveReference] = Field(default_factory=list)
    kg_risk_score: Optional[float] = None
    graph_evidence: list[dict] = Field(default_factory=list)
    suppressed_by_graph: bool = False
    votes: Optional[dict] = None             # V17 추가 정보 {v13,v14,graph}
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


# ── 헬퍼 ──────────────────────────────────────────────────────────────────────

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


def _stage(votes: dict) -> int:
    if votes.get("v13"):
        return 1
    if votes.get("v14"):
        return 2
    return 3  # graph-only


def _gen_meta(language: str, code: str, vuln: str) -> dict:
    """탐지된 취약점의 한국어 메타 생성 (DAST generateMeta와 대칭).

    베이스 instruct 모델 1회 호출. 실패해도 판정 결과엔 영향 없음(빈 문자열).
    """
    if not META_ENABLED:
        return {}
    prompt = (
        f'{language} 코드에서 "{vuln}" 취약점이 탐지되었습니다.\n'
        f"```\n{code[:1200]}\n```\n"
        "아래 JSON 형식으로만 응답하세요. 다른 텍스트는 포함하지 마세요.\n"
        '{"summary":"한 줄 요약 (한국어)",'
        '"attack":"공격 시나리오 한 문장 (한국어)",'
        '"fix":"해결 방법, 가능하면 수정 코드 한 줄 포함 (한국어)"}'
    )
    try:
        raw = llm_chat(META_MODEL,
                       [{"role": "user", "content": prompt}],
                       {"temperature": 0.2, "num_predict": 400}, timeout=90)
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


# 한 줄짜리 초단문(<80자)은 문맥이 없어 v13이 과탐(OOD) → 두 모델 합의(AND) 요구.
# 4벤치 저장예측 검증: 평균 F1 62.0→61.7로 손실 미미, 데모성 오탐 제거.
_SHORT_CODE = 80


def _analyze_one(language: str, code: str, file_path: Optional[str]) -> AnalyzeResponse:
    t0 = time.time()
    r = predict(code, language)
    v = r.get("votes") or {}
    if (len(code.strip()) < _SHORT_CODE and r["vulnerable"]
            and not v.get("graph") and not (v.get("v13") and v.get("v14"))):
        r["vulnerable"] = False
        r["vulnerability"], r["severity"], r["cvss"] = None, "NONE", "0.0"
    g = r.get("graph") or {}
    graph_ev = []
    if g.get("verdict") == "vuln":
        graph_ev.append({"category": g.get("category") or "", "verdict": "vuln",
                         "filename": file_path or "", "variable": "", "sink": "",
                         "source": "taint-graph", "path": [],
                         "summary": g.get("reason") or "", "confidence": 0.9})
    vuln_name = r.get("vulnerability") or ("NONE" if not r["vulnerable"] else "Security Vulnerability")
    severity = r.get("severity") or "NONE"
    cvss = _cvss_float(r.get("cvss"))
    meta, handoff, refs = {}, "", []
    if r["vulnerable"]:
        meta = _gen_meta(language, code, vuln_name)
        handoff = _handoff_prompt(language, code, vuln_name, severity, cvss)
        refs = _cve_refs(language, code, vuln_name)
    return AnalyzeResponse(
        language=language, file_path=file_path,
        detected=bool(r["vulnerable"]),
        stage=_stage(r.get("votes") or {}),
        vulnerability=vuln_name,
        severity=severity,
        cvss_score=cvss,
        attack=meta.get("attack", ""),
        fix=meta.get("fix", ""),
        summary=meta.get("summary", ""),
        ai_prompt=handoff,
        cve_references=refs,
        graph_evidence=graph_ev,
        votes=r.get("votes"),
        elapsed=round(time.time() - t0, 2),
    )


# ── 엔드포인트 ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "17.0.0",
            "ensemble": {"v13": V13_MODEL, "v16": V14_MODEL, "rule": "v13 OR v16.1 OR graph"},
            "llm_backend": "runpod" if use_runpod() else "ollama-local"}


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
            cvss_score=r.cvss_score, graph_evidence=r.graph_evidence,
            attack=r.attack, fix=r.fix, summary=r.summary,
            ai_prompt=r.ai_prompt, cve_references=r.cve_references,
            diff_line=_first_added_line(f.patch),
        ))
    return PrScanResponse(repo=req.repo, pr_number=req.pr_number,
                          total_files=len(req.files),
                          vulnerable_count=len(findings),
                          findings=findings, elapsed=round(time.time() - t0, 2))
