"""
ScanOps QLoRA v5 GGUF 변환 + Ollama 등록 (로컬 전용, HF 업로드 생략)
====================================================================
v5는 OWASP Benchmark 진단으로 드러난 학습데이터 불균형(안전 예시 1%)을
해소한 재학습 버전이다 (data/lora_train_v5.jsonl, 안전/NONE 40%).
어댑터는 models/qwen-security-qlora-v5/ 에 /final 없이 직접 저장됨.

단계:
  1. v5 어댑터 병합 → qwen-security-merged-v5/
  2. GGUF F16 변환
  3. Q4_K_M 양자화
  4. 로컬 Ollama 등록 (qwen2.5-coder-security-v5:latest)

실행:
  python scripts/convert_to_gguf_v5.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR / "scripts"))

from merge_and_convert import step1_merge, step2_convert, step3_quantize

ADAPTER_DIR = BASE_DIR / "models" / "qwen-security-qlora-v5"
MERGED_DIR  = BASE_DIR / "models" / "qwen-security-merged-v5"
F16_GGUF    = BASE_DIR / "models" / "qwen-security-v5.f16.gguf"
Q4_GGUF     = BASE_DIR / "models" / "qwen-security-v5.Q4_K_M.gguf"
MODELFILE   = BASE_DIR / "models" / "Modelfile_v5"
OLLAMA_NAME = "qwen2.5-coder-security-v5"

# v4와 동일한 추론 파라미터 (production 정합성 유지)
MODELFILE_CONTENT = f"""FROM {Q4_GGUF}

PARAMETER temperature 0.05
PARAMETER top_p 0.8
PARAMETER num_predict 512
PARAMETER repeat_penalty 1.3
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|endoftext|>"
PARAMETER stop "[EMPTY_151643]"
PARAMETER stop "\\n\\n\\n"
"""


def step4_register_ollama() -> None:
    print(f"[4/4] 로컬 Ollama 등록: {OLLAMA_NAME}")
    MODELFILE.parent.mkdir(exist_ok=True)
    MODELFILE.write_text(MODELFILE_CONTENT)
    subprocess.run(["ollama", "create", OLLAMA_NAME, "-f", str(MODELFILE)], check=True)
    print(f"      완료: ollama run {OLLAMA_NAME}")


def main() -> None:
    print("=" * 65)
    print("  ScanOps QLoRA v5 GGUF 변환 파이프라인 (안전코드 균형 재학습)")
    print("=" * 65)

    if not ADAPTER_DIR.exists() or not (ADAPTER_DIR / "adapter_model.safetensors").exists():
        print(f"오류: 어댑터 없음 — {ADAPTER_DIR}")
        print("먼저 실행: python -m scanops.models.train_qlora --data data/lora_train_v5.jsonl --tag v5")
        return

    step1_merge(ADAPTER_DIR, MERGED_DIR)
    step2_convert(MERGED_DIR, F16_GGUF)
    step3_quantize(F16_GGUF, Q4_GGUF)
    step4_register_ollama()

    print("\n" + "=" * 65)
    print("  완료!  로컬: ollama run " + OLLAMA_NAME)
    print("=" * 65)


if __name__ == "__main__":
    main()
