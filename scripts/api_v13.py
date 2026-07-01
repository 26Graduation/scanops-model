"""ScanOps V13 API — 파인튜닝 모델 + 코드그래프 (LLM ∨ graph)
================================================================
V13 배포용. Ollama 모델(v13) 단독으로는 taint 그래프가 빠지므로, 이 얇은 API가
LLM 판정 + 코드그래프 taint를 결합(R2: 그래프가 놓친 취약 보강)해 단일 엔드포인트로 제공한다.
벤치마크의 "V13 + 그래프" 성능과 동일. RAG/벡터DB는 쓰지 않는다.

실행:  uvicorn scripts.api_v13:app --host 0.0.0.0 --port 8100
환경변수: SCANOPS_V13_MODEL (기본 qwen2.5-coder-security-v13-7b:latest),
         OLLAMA_URL (기본 http://localhost:11434), SCANOPS_API_KEY(선택)
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

from scanops.core.ensemble import predict_single, V13_MODEL

app = FastAPI(title="ScanOps V13 API (LLM + Graph)", version="13.0.0")
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
    source: Optional[str] = None            # llm | graph | None
    votes: dict                              # {llm, graph}
    graph: dict                              # {verdict, category, reason}
    elapsed: float


@app.get("/health")
def health():
    return {"status": "ok", "version": "13.0.0",
            "system": {"model": V13_MODEL, "rule": "LLM OR graph(taint)", "rag": False}}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest, _=Security(_require_api_key)):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="empty code")
    t0 = time.time()
    try:
        r = predict_single(req.code, req.language)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"model backend error: {e}")
    r["elapsed"] = round(time.time() - t0, 2)
    return r
