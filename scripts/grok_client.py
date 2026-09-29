"""
Grok API client for ScanOps security analysis.
Replaces Ollama + Gemma 2B (localhost:11434) with xAI Grok API.

Usage:
    from grok_client import query_llm
    response, elapsed = query_llm(prompt, system_prompt)
"""

import json
import os
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

# .env 파일 로드 (scanops-model 루트)
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

GROK_API_URL = "https://api.x.ai/v1/chat/completions"

DEFAULT_MODEL = "grok-3-mini"  # 비용 효율 (성능 우선: "grok-3")

SECURITY_SYSTEM_PROMPT = (
    "You are a cybersecurity expert specializing in vulnerability analysis. "
    "Identify vulnerabilities with CWE ID, severity (CRITICAL/HIGH/MEDIUM/LOW), "
    "attack vector, and provide fixed code. Be concise."
)


def query_llm(
    prompt: str,
    system_prompt: str = SECURITY_SYSTEM_PROMPT,
    model: str = DEFAULT_MODEL,
    temperature: float = 0.0,
    max_tokens: int = 512,
) -> tuple[str, float]:
    """
    Send a prompt to Grok API and return (response_text, elapsed_seconds).

    Compatible interface with test_ollama.py::generate().
    """
    api_key = os.getenv("XAI_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "XAI_API_KEY 환경변수가 설정되지 않았습니다. "
            "scanops-model/.env 파일에 XAI_API_KEY=xai-... 를 추가하세요."
        )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    t0 = time.perf_counter()
    try:
        with httpx.Client(timeout=120.0) as client:
            resp = client.post(GROK_API_URL, headers=headers, json=payload)
    except httpx.ConnectError as e:
        raise ConnectionError(f"Grok API 연결 실패 (네트워크 오류): {e}") from e
    except httpx.TimeoutException as e:
        raise TimeoutError(f"Grok API 응답 시간 초과: {e}") from e

    elapsed = round(time.perf_counter() - t0, 2)

    if resp.status_code == 401:
        raise PermissionError("XAI_API_KEY가 유효하지 않습니다 (401 Unauthorized).")
    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After", "잠시 후")
        raise RuntimeError(f"Rate limit 초과 (429). {retry_after}초 후 재시도하세요.")
    if resp.status_code != 200:
        raise RuntimeError(
            f"Grok API 오류 {resp.status_code}: {resp.text[:200]}"
        )

    body = resp.json()
    text = body["choices"][0]["message"]["content"]
    return text, elapsed


def main():
    """연결 테스트 (test_ollama.py 대응)"""
    test_prompt = "What is CVE? Answer in 2 sentences."

    print("Grok API 연결 테스트")
    print(f"  모델  : {DEFAULT_MODEL}")
    print(f"  질문  : {test_prompt}\n")

    try:
        answer, elapsed = query_llm(test_prompt)
        print(f"[응답]\n{answer}\n")
        print(f"응답 시간: {elapsed:.2f}초")
        print("Grok API 연결: 성공")
    except Exception as e:
        print(f"Grok API 연결: 실패 ({e})")


if __name__ == "__main__":
    main()
