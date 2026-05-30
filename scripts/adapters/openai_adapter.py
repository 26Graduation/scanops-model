"""
ScanOps 어댑터 — OpenAI API (친구들이 GPT로 비교할 때 사용)

필요한 것:
    pip install openai
    .env 파일에 OPENAI_API_KEY=sk-... 추가

실행 예시:
    python -m adapters.openai_adapter                    # gpt-4o-mini (기본)
    python -m adapters.openai_adapter --model gpt-4o     # GPT-4o
"""

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")

from benchmark_core import PROMPT_TMPL, run_benchmark, save_html

try:
    from openai import OpenAI
except ImportError:
    print("openai 패키지가 없습니다. pip install openai 실행 후 재시도하세요.")
    sys.exit(1)

MODEL = "gpt-4o-mini"

SYSTEM_PROMPT = (
    "You are a cybersecurity expert specializing in vulnerability analysis. "
    "Identify vulnerabilities with CWE ID, severity (CRITICAL/HIGH/MEDIUM/LOW), "
    "attack vector, and provide fixed code. Be concise."
)


def query(language: str, code: str, model: str = MODEL) -> tuple[str, float]:
    """benchmark_core.QueryFn 인터페이스 구현."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise EnvironmentError(".env 파일에 OPENAI_API_KEY 가 없습니다.")

    client  = OpenAI(api_key=api_key)
    prompt  = PROMPT_TMPL.format(language=language, code=code)

    t0 = time.perf_counter()
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        temperature=0.0,
        max_tokens=512,
    )
    elapsed = round(time.perf_counter() - t0, 2)
    return resp.choices[0].message.content, elapsed


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=MODEL,
                        help="OpenAI 모델명 (예: gpt-4o, gpt-4o-mini, gpt-4-turbo)")
    args = parser.parse_args()

    def _query(language, code):
        return query(language, code, model=args.model)

    summary = run_benchmark(_query, model_name=f"OpenAI — {args.model}")
    out = save_html(summary)
    print(f"HTML: {out}")
