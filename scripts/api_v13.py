"""ScanOps V13 API — 파인튜닝 모델 + 코드그래프 (LLM ∨ graph), RAG 미사용
================================================================
백엔드(scanops-backend `ScanopsModelClient`)가 기대하는 기존 계약(api_server.py 스키마)을
**그대로 유지**하면서, 내부 분석만 v13+코드그래프 앙상블(RAG 없음)로 제공한다.
→ 백엔드 코드 무수정으로 교체 가능.

엔드포인트: GET /health · POST /analyze · POST /analyze/batch · POST /analyze/pr
실행:  uvicorn scripts.api_v13:app --host 0.0.0.0 --port 8100
환경변수: SCANOPS_V13_MODEL, OLLAMA_URL, SCANOPS_API_KEY(선택, 헤더 X-Scanops-Key)
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

from scanops.core.ensemble import predict_single, V13_MODEL

app = FastAPI(title="ScanOps V13 API (LLM + Graph, no RAG)", version="13.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_API_KEY = os.getenv("SCANOPS_API_KEY", "")
_API_KEY_HEADER = APIKeyHeader(name="X-Scanops-Key", auto_error=False)


def _auth(key: Optional[str] = Security(_API_KEY_HEADER)) -> None:
    if _API_KEY and key != _API_KEY:
        raise HTTPException(status_code=401, detail="invalid or missing X-Scanops-Key")


# ── 백엔드 계약 스키마 (api_server.py와 동일 필드) ────────────────────────────
class AnalyzeRequest(BaseModel):
    language: str
    code: str
    file_path: Optional[str] = None
    use_rag: bool = True                 # 받되 무시 (V13은 RAG 미사용)


class CveReference(BaseModel):
    cve_id: str
    severity: str
    base_score: float
    cwe_id: str
    description: str


class AnalyzeResponse(BaseModel):
    language: str
    file_path: Optional[str] = None
    detected: bool
    stage: int = 1                       # 항상 1 (2-stage adaptive 없음)
    vulnerability: str
    severity: str
    cvss_score: Optional[float] = None
    attack: str = ""
    fix: str = ""
    cve_references: list[CveReference] = Field(default_factory=list)
    suppressed_by_graph: bool = False
    votes: dict = Field(default_factory=dict)   # {llm, graph} (근거·디버깅용 추가필드)
    elapsed: float = 0.0


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
    cvss_score: Optional[float] = None
    attack: str = ""
    fix: str = ""
    cve_references: list[CveReference] = Field(default_factory=list)
    diff_line: Optional[int] = None


class PrScanResponse(BaseModel):
    repo: str
    pr_number: int
    total_files: int
    vulnerable_count: int
    findings: list[PrFinding]
    elapsed: float


# ── 공통 헬퍼 ──────────────────────────────────────────────────────────────────
def _to_float(cvss: Optional[str]) -> Optional[float]:
    try:
        f = float(cvss)
        return f if f > 0 else None
    except (TypeError, ValueError):
        return None


def _detect_language(filename: str) -> str:
    ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
    return {"py": "Python", "java": "Java", "js": "Node.js / Express",
            "ts": "TypeScript", "php": "PHP", "go": "Go", "rb": "Ruby",
            "cs": "C#", "c": "C", "cpp": "C++", "cc": "C++"}.get(ext, "Python")


def _first_diff_line(patch: Optional[str]) -> Optional[int]:
    """git patch에서 첫 추가 라인의 새 파일 기준 줄번호."""
    if not patch:
        return None
    m = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)", patch)
    return int(m.group(1)) if m else None


def _analyze_one(language: str, code: str, file_path: Optional[str] = None) -> AnalyzeResponse:
    t0 = time.time()
    r = predict_single(code, language)
    return AnalyzeResponse(
        language=language, file_path=file_path,
        detected=r["vulnerable"], stage=1,
        vulnerability=r.get("vulnerability") or "NONE",
        severity=r.get("severity") or "NONE",
        cvss_score=_to_float(r.get("cvss")),
        attack=(r.get("graph") or {}).get("reason") or "",
        fix="", cve_references=[],
        suppressed_by_graph=False,
        votes=r.get("votes", {}),
        elapsed=round(time.time() - t0, 2),
    )


# ── 엔드포인트 ─────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "version": "13.0.0",
            "system": {"model": V13_MODEL, "rule": "LLM OR graph(taint)", "rag": False}}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest, _=Security(_auth)):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="empty code")
    try:
        return _analyze_one(req.language, req.code, req.file_path)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"model backend error: {e}")


@app.post("/analyze/batch", response_model=BatchResponse)
def analyze_batch(req: BatchRequest, _=Security(_auth)):
    t0 = time.time()
    results: list[AnalyzeResponse] = []
    for f in req.files:
        if not f.code.strip():
            continue
        res = _analyze_one(f.language, f.code, f.file_path)
        results.append(res)
        if req.stop_on_first and res.detected:
            break
    return BatchResponse(total=len(results),
                         detected_count=sum(1 for r in results if r.detected),
                         results=results, elapsed=round(time.time() - t0, 2))


@app.post("/analyze/pr", response_model=PrScanResponse)
def analyze_pr(req: PrScanRequest, _=Security(_auth)):
    t0 = time.time()
    findings: list[PrFinding] = []
    for f in req.files:
        if not f.content.strip():
            continue
        lang = _detect_language(f.filename)
        r = predict_single(f.content, lang)
        findings.append(PrFinding(
            filename=f.filename, detected=r["vulnerable"],
            vulnerability=r.get("vulnerability") or "NONE",
            severity=r.get("severity") or "NONE",
            cvss_score=_to_float(r.get("cvss")),
            attack=(r.get("graph") or {}).get("reason") or "",
            fix="", cve_references=[],
            diff_line=_first_diff_line(f.patch),
        ))
    return PrScanResponse(
        repo=req.repo, pr_number=req.pr_number,
        total_files=len(req.files),
        vulnerable_count=sum(1 for f in findings if f.detected),
        findings=findings, elapsed=round(time.time() - t0, 2))
