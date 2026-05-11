"""
ScanOps 어댑터 — Ollama (로컬 모델용 템플릿)

Ollama로 돌리는 어떤 모델이든 MODEL 변수만 바꾸면 된다.
예: gemma:2b, llama3:8b, mistral:7b, codellama:7b, ...

실행 예시:
    ollama pull llama3:8b          # 모델 먼저 받기
    python -m adapters.ollama_adapter --model llama3:8b
"""

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmark_core import PROMPT_TMPL, run_benchmark, save_html

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL      = "gemma:2b"   # ← 여기를 바꾸면 다른 모델로 테스트 가능


def query(language: str, code: str, model: str = MODEL) -> tuple[str, float]:
    """benchmark_core.QueryFn 인터페이스 구현."""
    prompt  = PROMPT_TMPL.format(language=language, code=code)
    payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(
        OLLAMA_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = json.loads(resp.read())
    return body["response"], round(time.perf_counter() - t0, 2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=MODEL, help="Ollama 모델명 (예: llama3:8b)")
    args = parser.parse_args()

    def _query(language, code):
        return query(language, code, model=args.model)

    summary = run_benchmark(_query, model_name=f"Ollama — {args.model}")
    out = save_html(summary)
    print(f"HTML: {out}")
