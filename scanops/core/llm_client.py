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
# cold start(워커 기동+모델 로드, 최악엔 새 호스트 이미지 pull ~4분)가 첫 요청에
# 얹힐 수 있어 넉넉히. 웜 상태엔 어차피 수 초 내 완료라 영향 없음.
RUNPOD_TIMEOUT = int(os.getenv("RUNPOD_TIMEOUT", "420"))


def use_runpod() -> bool:
    return bool(RUNPOD_ENDPOINT_ID)


# rebuild 워커는 raw completion도 받는다 — 학습 템플릿과 동일한 ChatML 래핑을
# 호출측이 만들어 보내는 판정 경로(<think> 방지, eval_gguf.py와 동일 지점).
LLAMA_SERVER_URL = os.getenv("LLAMA_SERVER_URL", "http://localhost:8080")


def completion(prompt: str, options: dict, timeout: int = 300) -> str:
    """raw completion 호출 → 응답 텍스트. RunPod 워커 또는 로컬 llama-server."""
    if use_runpod():
        return _runpod_call({"prompt": prompt, "options": options})
    r = requests.post(f"{LLAMA_SERVER_URL.rstrip('/')}/completion", json={
        "prompt": prompt,
        "n_predict": int(options.get("num_predict", 256)),
        "temperature": float(options.get("temperature", 0.0)),
        "stop": options.get("stop", ["<|im_end|>"]),
    }, timeout=timeout)
    r.raise_for_status()
    return r.json().get("content", "")


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
    return _runpod_call({"model": model, "messages": messages, "options": options})


def _runpod_call(input_payload: dict) -> str:
    import time

    base = f"https://api.runpod.ai/v2/{RUNPOD_ENDPOINT_ID}"
    hdrs = {"Authorization": f"Bearer {RUNPOD_API_KEY}"}
    r = requests.post(f"{base}/runsync", json={
        "input": input_payload,
    }, headers=hdrs, timeout=RUNPOD_TIMEOUT)
    r.raise_for_status()
    data = r.json()

    # cold start 시 runsync는 ~90초 후 IN_QUEUE/IN_PROGRESS를 반환하고 job은 계속 돈다
    # → 에러가 아니라 "아직"이므로 /status/{id} 로 완료까지 폴링 (총 RUNPOD_TIMEOUT 한도).
    t0 = time.time()
    while data.get("status") in ("IN_QUEUE", "IN_PROGRESS"):
        if time.time() - t0 > RUNPOD_TIMEOUT:
            raise RuntimeError(f"RunPod job timeout({RUNPOD_TIMEOUT}s): {data.get('id')}")
        time.sleep(3)
        r = requests.get(f"{base}/status/{data['id']}", headers=hdrs, timeout=30)
        r.raise_for_status()
        data = r.json()

    if data.get("status") != "COMPLETED":
        raise RuntimeError(f"RunPod job {data.get('status')}: {str(data)[:300]}")
    out = data.get("output") or {}
    if isinstance(out, dict) and "error" in out:
        raise RuntimeError(f"RunPod worker error: {out['error']}")
    return (out or {}).get("content", "")
