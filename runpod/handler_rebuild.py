"""RunPod Serverless 워커 — llama.cpp 서버 프록시 (rebuild Qwen3.5-9B 단일 모델)
================================================================================
입력  {"input": {"prompt": "...", "options": {...}}}          ← 판정 (raw completion,
      학습 템플릿과 동일한 ChatML 래핑은 호출측(llm_client)이 수행)
      {"input": {"messages": [...], "options": {...}}}        ← 메타 생성 (chat 템플릿)
출력  {"content": "<모델 응답 텍스트>"}

모델은 이미지에 굽지 않고 네트워크 볼륨(/runpod-volume)에서 로드한다.
→ 이미지가 작아 릴리즈가 빠르고, 모델 교체는 볼륨 파일 교체+MODEL_PATH 변경만.
Qwen3.5 하이브리드 linear-attention은 llama.cpp가 네이티브 지원(transformers 커널
지연 이슈 회피 — rebuild 라운드에서 확인).
"""
from __future__ import annotations

import os
import re
import subprocess
import time

import requests
import runpod

MODEL_PATH = os.getenv("MODEL_PATH", "/runpod-volume/serve/scanops-rebuild-9b-q4km.gguf")
CTX = os.getenv("LLAMA_CTX", "8192")
PARALLEL = os.getenv("LLAMA_PARALLEL", "2")
LLAMA = "http://127.0.0.1:8080"

_BIN_CANDIDATES = ("/app/llama-server", "/llama-server", "/usr/local/bin/llama-server")


def _llama_bin() -> str:
    for p in _BIN_CANDIDATES:
        if os.path.exists(p):
            return p
    return "llama-server"


def _start_llama() -> None:
    # 로그를 컨테이너 stdout으로 그대로 흘려 RunPod 콘솔에서 로드/크래시를 볼 수 있게 함
    print(f"[rebuild] LLAMA_STARTING bin={_llama_bin()} model={MODEL_PATH} "
          f"exists={os.path.exists(MODEL_PATH)}", flush=True)
    subprocess.Popen(
        [_llama_bin(), "-m", MODEL_PATH, "-ngl", "99", "-c", CTX,
         "--parallel", PARALLEL, "--host", "127.0.0.1", "--port", "8080"])
    # 볼륨에서 5.5GB 로드 → 최대 5분 대기
    for i in range(150):
        try:
            if requests.get(f"{LLAMA}/health", timeout=2).status_code == 200:
                print(f"[rebuild] LLAMA_READY after {i*2}s", flush=True)
                return
        except Exception:  # noqa: BLE001
            pass
        time.sleep(2)
    raise RuntimeError(f"llama-server 기동 실패: {MODEL_PATH}")


_start_llama()
print("[rebuild] SDK_STARTING runpod-python", flush=True)


def _strip_think(text: str) -> str:
    return re.sub(r"<think>.*?(</think>|$)", "", text, flags=re.S).strip()


def handler(job):
    print(f"[rebuild] JOB_TAKEN {job.get('id')}", flush=True)
    inp = job.get("input") or {}
    options = inp.get("options") or {}
    try:
        if inp.get("prompt"):
            r = requests.post(f"{LLAMA}/completion", json={
                "prompt": inp["prompt"],
                "n_predict": int(options.get("num_predict", 256)),
                "temperature": float(options.get("temperature", 0.0)),
                "stop": options.get("stop", ["<|im_end|>"]),
            }, timeout=280)
            r.raise_for_status()
            return {"content": _strip_think(r.json().get("content", ""))}
        if inp.get("messages"):
            r = requests.post(f"{LLAMA}/v1/chat/completions", json={
                "messages": inp["messages"],
                "max_tokens": int(options.get("num_predict", 512)),
                "temperature": float(options.get("temperature", 0.2)),
            }, timeout=280)
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            return {"content": _strip_think(content)}
        return {"error": "prompt or messages required"}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


runpod.serverless.start({"handler": handler})
