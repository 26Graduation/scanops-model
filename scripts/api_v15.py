"""ScanOps V15 API — v13 ∨ v14 OR 앙상블 서빙 (FastAPI)
================================================================
백엔드(Spring AiRouter의 CUSTOM 엔진)가 호출하는 단일 엔드포인트. 내부에서 v13·v14 두
Ollama 모델 + 코드그래프를 OR로 결합해 최종 판정을 반환한다.

실행:  uvicorn scripts.api_v15:app --host 0.0.0.0 --port 8100
환경변수:
  SCANOPS_V13_MODEL (기본 qwen2.5-coder-security-v13-7b:latest)
  SCANOPS_V14_MODEL (기본 qwen2.5-coder-security-v14-7b:latest)
  OLLAMA_URL        (기본 http://localhost:11434)
  SCANOPS_API_KEY   (설정 시 X-API-Key 헤더 필요)
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field

from scanops.core.ensemble import predict, V13_MODEL, V14_MODEL

app = FastAPI(title="ScanOps V15 Ensemble API", version="15.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_API_KEY = os.getenv("SCANOPS_API_KEY", "")
_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def _require_api_key(key: Optional[str] = Security(_API_KEY_HEADER)) -> None:
    if _API_KEY and key != _API_KEY:
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


class AnalyzeRequest(BaseModel):
    code: str = Field(..., description="분석할 소스코드")
    language: str = Field("Python", description="언어 (예: Python, Java, Node.js / Express)")


class AnalyzeResponse(BaseModel):
    vulnerable: bool
    vulnerability: Optional[str] = None
    severity: Optional[str] = None
    cvss: Optional[str] = None
    source: Optional[str] = None            # v13 | v14 | graph | None
    votes: dict                              # {v13, v14, graph}
    graph: dict                              # {verdict, category, reason}
    elapsed: float


@app.get("/health")
def health():
    return {"status": "ok", "version": "15.0.0",
            "ensemble": {"v13": V13_MODEL, "v14": V14_MODEL, "rule": "v13 OR v14 OR graph"}}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest, _=Security(_require_api_key)):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="empty code")
    t0 = time.time()
    try:
        r = predict(req.code, req.language)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"model backend error: {e}")
    r["elapsed"] = round(time.time() - t0, 2)
    return r
