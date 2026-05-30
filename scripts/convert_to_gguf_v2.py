"""QLoRA v2 모델 GGUF 변환 + Ollama 등록 파이프라인.

merge_and_convert.py의 로직을 사용하되 v2 경로/모델명으로 등록.
"""

from __future__ import annotations

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR / "scripts"))

from merge_and_convert import step1_merge, step2_convert, step3_quantize, step4_ollama  # noqa

ADAPTER_DIR   = BASE_DIR / "models" / "qwen-security-qlora"
MERGED_DIR    = BASE_DIR / "models" / "qwen-security-merged-v2"
F16_GGUF      = BASE_DIR / "models" / "qwen-security-v2.f16.gguf"
Q4_GGUF       = BASE_DIR / "models" / "qwen-security-v2.Q4_K_M.gguf"
MODELFILE_V2  = BASE_DIR / "models" / "Modelfile_v2"
OLLAMA_NAME   = "qwen2.5-coder-security-v2"

MODELFILE_CONTENT = f"""FROM {Q4_GGUF}

PARAMETER temperature 0.05
PARAMETER top_p 0.8
PARAMETER num_predict 400
PARAMETER repeat_penalty 1.3
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|endoftext|>"
PARAMETER stop "[EMPTY_151643]"
PARAMETER stop "\\n\\n\\n"
"""


def register_ollama_v2() -> None:
    import subprocess
    print(f"[4/4] Ollama 등록: {OLLAMA_NAME}")
    MODELFILE_V2.write_text(MODELFILE_CONTENT)
    subprocess.run(["ollama", "create", OLLAMA_NAME, "-f", str(MODELFILE_V2)], check=True)
    print(f"\n완료: ollama run {OLLAMA_NAME}")


def main() -> None:
    print("=" * 60)
    print("ScanOps — QLoRA v2 GGUF 변환 파이프라인")
    print("=" * 60)

    step1_merge(ADAPTER_DIR, MERGED_DIR)
    step2_convert(MERGED_DIR, F16_GGUF)
    step3_quantize(F16_GGUF, Q4_GGUF)
    register_ollama_v2()

    print("\n벤치마크 실행:")
    print("  python scripts/benchmark_qwen_rag.py")


if __name__ == "__main__":
    main()
