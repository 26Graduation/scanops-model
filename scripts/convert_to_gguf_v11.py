"""
ScanOps QLoRA v11 (3B) GGUF 변환 + Ollama 등록
====================================================================
v11은 Qwen2.5-Coder-**3B** 베이스로 Colab에서 학습한 모델이다(어댑터만 받음).
OWASP 외부 벤치마크에서 탐지력(recall 89%) + CWE 식별(87%)이 Grok을 초월한,
현재 최고의 "탐지기" 모델. (오탐 억제는 코드 그래프 taint 레이어가 담당)

전제: Colab에서 받은 adapter_3b_v11.zip 을 아래 경로에 풀어둔다:
  models/qwen-security-qlora-v11/   (adapter_model.safetensors 등)

단계:
  1. 3B 베이스에 v11 어댑터 병합 → qwen-security-merged-v11/
  2. GGUF F16 변환 (config.json에서 3B 차원 자동 인식)
  3. Q4_K_M 양자화 (~2GB)
  4. 로컬 Ollama 등록 (qwen2.5-coder-security-v11)

실행:
  python scripts/convert_to_gguf_v11.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR / "scripts"))

import merge_and_convert as mc
# ★ v11은 3B 베이스 — merge_and_convert의 기본값(1.5B)을 덮어쓴다.
mc.BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-3B-Instruct"
from merge_and_convert import step1_merge, step2_convert, step3_quantize

ADAPTER_DIR = BASE_DIR / "models" / "qwen-security-qlora-v11"
MERGED_DIR  = BASE_DIR / "models" / "qwen-security-merged-v11"
F16_GGUF    = BASE_DIR / "models" / "qwen-security-v11.f16.gguf"
Q4_GGUF     = BASE_DIR / "models" / "qwen-security-v11.Q4_K_M.gguf"
MODELFILE   = BASE_DIR / "models" / "Modelfile_v11"
OLLAMA_NAME = "qwen2.5-coder-security-v11"

MODELFILE_CONTENT = f"""FROM {Q4_GGUF}

PARAMETER temperature 0.05
PARAMETER top_p 0.8
PARAMETER num_predict 256
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
    print("  ScanOps QLoRA v11 (3B) GGUF 변환 — 최고 탐지기")
    print("=" * 65)

    if not (ADAPTER_DIR / "adapter_model.safetensors").exists():
        print(f"오류: 어댑터 없음 — {ADAPTER_DIR}/adapter_model.safetensors")
        print("Colab에서 받은 adapter_3b_v11.zip 을 아래에 풀어주세요:")
        print(f"  unzip ~/Downloads/adapter_3b_v11.zip -d {ADAPTER_DIR}")
        return

    step1_merge(ADAPTER_DIR, MERGED_DIR)
    step2_convert(MERGED_DIR, F16_GGUF)
    step3_quantize(F16_GGUF, Q4_GGUF)
    step4_register_ollama()
    print("\n완료! ollama run " + OLLAMA_NAME)


if __name__ == "__main__":
    main()
