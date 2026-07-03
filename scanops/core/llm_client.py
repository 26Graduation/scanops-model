"""LLM chat 라우터 — 로컬 Ollama ↔ RunPod Serverless 투명 전환
================================================================
GPU 비용 절감의 핵심: REST 계약(FastAPI)·백엔드(Java)는 그대로 두고,
**GPU가 필요한 LLM 호출만** RunPod serverless 워커로 보낸다.

환경변수:
  RUNPOD_ENDPOINT_ID  — 설정되면 RunPod 경유 (미설정 시 로컬 Ollama)
  RUNPOD_API_KEY      — RunPod Bearer 키
  OLLAMA_CHAT_URL     — 로컬 모드 주소 (기본 http://localhost:11434/api/chat)

RunPod 워커(runpod/handler.py)는 {"input": {"messages", "model", "options"}} 를 받아
{"output": {"content": "..."}} 를 반환한다. cold start 대비 타임아웃은 넉넉히.
"""
from __future__ import annotations

import os

import requests

RUNPOD_ENDPOINT_ID = os.getenv("RUNPOD_ENDPOINT_ID", "")
RUNPOD_API_KEY = os.getenv("RUNPOD_API_KEY", "")
OLLAMA_CHAT_URL = os.getenv("OLLAMA_CHAT_URL",
                            os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
                            .removesuffix("/api/generate") + "/api/chat")
# cold start(워커 기동+모델 로드)가 첫 요청에 얹힐 수 있어 로컬보다 길게.
RUNPOD_TIMEOUT = int(os.getenv("RUNPOD_TIMEOUT", "180"))


def use_runpod() -> bool:
    return bool(RUNPOD_ENDPOINT_ID)


def chat(model: str, messages: list[dict], options: dict, timeout: int = 90) -> str:
    """chat 호출 → 응답 content 문자열. 라우팅은 환경변수로 결정."""
    if use_runpod():
        return _chat_runpod(model, messages, options)
    return _chat_ollama(model, messages, options, timeout)


def _chat_ollama(model: str, messages: list[dict], options: dict, timeout: int) -> str:
    r = requests.post(OLLAMA_CHAT_URL, json={
        "model": model, "messages": messages, "stream": False, "options": options,
    }, timeout=timeout)
    r.raise_for_status()
    return r.json().get("message", {}).get("content", "")


def _chat_runpod(model: str, messages: list[dict], options: dict) -> str:
    url = f"https://api.runpod.ai/v2/{RUNPOD_ENDPOINT_ID}/runsync"
    r = requests.post(url, json={
        "input": {"model": model, "messages": messages, "options": options},
    }, headers={"Authorization": f"Bearer {RUNPOD_API_KEY}"}, timeout=RUNPOD_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    status = data.get("status")
    if status != "COMPLETED":
        raise RuntimeError(f"RunPod job {status}: {str(data)[:300]}")
    out = data.get("output") or {}
    if isinstance(out, dict) and "error" in out:
        raise RuntimeError(f"RunPod worker error: {out['error']}")
    return (out or {}).get("content", "")
