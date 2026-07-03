"""RunPod Serverless 워커 — Ollama chat 프록시 (V17: v13 + v16.1)
================================================================
입력  {"input": {"model": "...", "messages": [...], "options": {...}}}
출력  {"content": "<모델 응답 텍스트>"}

컨테이너 기동 시 Ollama 서버를 띄우고(모델은 이미지에 베이크됨) 요청을 로컬
/api/chat 으로 중계한다. 범용 프록시라 앙상블 멤버 추가/교체 시 이미지에
모델만 더 구우면 됨(핸들러 수정 불필요).
"""
from __future__ import annotations

import os
import subprocess
import time

import requests
import runpod

OLLAMA = "http://127.0.0.1:11434"
# 워커가 서빙하는 모델만 허용 (판정 모델 2개 + 메타 생성용 베이스)
ALLOWED_PREFIX = ("qwen2.5-coder-security-", "qwen2.5-coder:7b-instruct")


def _start_ollama() -> None:
    subprocess.Popen(["ollama", "serve"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            requests.get(f"{OLLAMA}/api/tags", timeout=2)
            return
        except Exception:  # noqa: BLE001
            time.sleep(1)
    raise RuntimeError("ollama serve 기동 실패")


_start_ollama()

# 웜업(선택): 기본 모델을 미리 로드해 첫 요청 지연 단축
_WARM = os.getenv("WARM_MODEL", "")
if _WARM:
    try:
        requests.post(f"{OLLAMA}/api/chat", json={
            "model": _WARM, "messages": [{"role": "user", "content": "ping"}],
            "stream": False, "options": {"num_predict": 1},
        }, timeout=300)
    except Exception:  # noqa: BLE001
        pass


def handler(job):
    inp = job.get("input") or {}
    model = str(inp.get("model") or "")
    messages = inp.get("messages") or []
    options = inp.get("options") or {}
    if not model.startswith(ALLOWED_PREFIX):
        return {"error": f"model not allowed: {model}"}
    if not messages:
        return {"error": "messages required"}
    try:
        r = requests.post(f"{OLLAMA}/api/chat", json={
            "model": model, "messages": messages, "stream": False, "options": options,
        }, timeout=300)
        r.raise_for_status()
        return {"content": r.json().get("message", {}).get("content", "")}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


runpod.serverless.start({"handler": handler})
