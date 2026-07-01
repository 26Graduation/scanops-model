"""
ScanOps QLoRA v12 (3B) GGUF 변환 + Ollama 등록
====================================================================
v12는 **OWASP를 학습에서 제외한** clean 데이터셋(264개, 16언어)으로 학습한 모델.
Colab에서 받은 adapter_v12.zip 을 아래 경로에 풀어둔다:
  models/qwen-security-qlora-v12/   (adapter_model.safetensors 등)

단계:
  1. 3B 베이스에 v12 어댑터 병합 → qwen-security-merged-v12/
  2. GGUF F16 변환
  3. Q4_K_M 양자화 (~2GB)
  4. 로컬 Ollama 등록 (qwen2.5-coder-security-v12)

실행:
  unzip ~/Downloads/adapter_v12.zip -d models/qwen-security-qlora-v12
  python scripts/convert_to_gguf_v12.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR / "scripts"))

import merge_and_convert as mc
mc.BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-3B-Instruct"      # v12도 3B 베이스
from merge_and_convert import step1_merge, step2_convert, step3_quantize

ADAPTER_DIR = BASE_DIR / "models" / "qwen-security-qlora-v12"
MERGED_DIR  = BASE_DIR / "models" / "qwen-security-merged-v12"
F16_GGUF    = BASE_DIR / "models" / "qwen-security-v12.f16.gguf"
Q4_GGUF     = BASE_DIR / "models" / "qwen-security-v12.Q4_K_M.gguf"
MODELFILE   = BASE_DIR / "models" / "Modelfile_v12"
OLLAMA_NAME = "qwen2.5-coder-security-v12"

# 서빙 파라미터: v11에서 재현율-최적으로 검증된 값으로 시작.
# (v12는 학습 후 scripts/grid_llm_hybrid.py로 재탐색 권장 — 양자화 민감성 때문)
MODELFILE_CONTENT = f"""FROM {Q4_GGUF}

PARAMETER temperature 0
PARAMETER top_p 0.8
PARAMETER num_predict 256
PARAMETER repeat_penalty 1.3
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|endoftext|>"
PARAMETER stop "[EMPTY_151643]"
"""


def step4_register_ollama() -> None:
    print(f"[4/4] 로컬 Ollama 등록: {OLLAMA_NAME}")
    MODELFILE.parent.mkdir(exist_ok=True)
    MODELFILE.write_text(MODELFILE_CONTENT)
    subprocess.run(["ollama", "create", OLLAMA_NAME, "-f", str(MODELFILE)], check=True)
    print(f"      완료: ollama run {OLLAMA_NAME}")


def main() -> None:
    print("=" * 65)
    print("  ScanOps QLoRA v12 (3B, OWASP-free) GGUF 변환")
    print("=" * 65)

    if not (ADAPTER_DIR / "adapter_model.safetensors").exists():
        print(f"오류: 어댑터 없음 — {ADAPTER_DIR}/adapter_model.safetensors")
        print("Colab에서 받은 adapter_v12.zip 을 아래에 풀어주세요:")
        print(f"  unzip ~/Downloads/adapter_v12.zip -d {ADAPTER_DIR}")
        return

    step1_merge(ADAPTER_DIR, MERGED_DIR)
    step2_convert(MERGED_DIR, F16_GGUF)
    step3_quantize(F16_GGUF, Q4_GGUF)
    step4_register_ollama()
    print("\n완료! ollama run " + OLLAMA_NAME)


if __name__ == "__main__":
    main()
