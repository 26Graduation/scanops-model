"""
ScanOps 어댑터 — xAI Grok API (우리 팀 모델)

benchmark_core.run_benchmark()에 전달하는 query 함수를 제공한다.

실행 예시:
    python -m adapters.grok_adapter          # 연결 테스트
    python benchmark_compare.py grok         # 비교 벤치마크에서 사용
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmark_core import PROMPT_TMPL, run_benchmark, save_html
from grok_client import query_llm

MODEL_NAME = "ScanOps — Grok API (grok-3)"


def query(language: str, code: str) -> tuple[str, float]:
    """benchmark_core.QueryFn 인터페이스 구현."""
    prompt = PROMPT_TMPL.format(language=language, code=code)
    return query_llm(prompt)


if __name__ == "__main__":
    summary = run_benchmark(query, model_name=MODEL_NAME)
    out = save_html(summary)
    print(f"HTML: {out}")
