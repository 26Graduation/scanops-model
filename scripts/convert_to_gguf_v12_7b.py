"""
ScanOps QLoRA v12-7B GGUF 변환 + Ollama 등록
====================================================================
v12 7B 어댑터(adapter_v12_7b.zip)를 받아서 변환한다. 3B 버전과 동일,
베이스만 Qwen2.5-Coder-7B-Instruct.

  unzip ~/Downloads/adapter_v12_7b.zip -d models/qwen-security-qlora-v12-7b
  python scripts/convert_to_gguf_v12_7b.py

산출: qwen2.5-coder-security-v12-7b (Ollama). Q4 ≈ 4.5GB.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR / "scripts"))

import merge_and_convert as mc
mc.BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-7B-Instruct"      # ★ 7B 베이스
from merge_and_convert import step1_merge, step2_convert, step3_quantize

ADAPTER_DIR = BASE_DIR / "models" / "qwen-security-qlora-v12-7b"
MERGED_DIR  = BASE_DIR / "models" / "qwen-security-merged-v12-7b"
F16_GGUF    = BASE_DIR / "models" / "qwen-security-v12-7b.f16.gguf"
Q4_GGUF     = BASE_DIR / "models" / "qwen-security-v12-7b.Q4_K_M.gguf"
MODELFILE   = BASE_DIR / "models" / "Modelfile_v12_7b"
OLLAMA_NAME = "qwen2.5-coder-security-v12-7b"

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
    print("  ScanOps QLoRA v12-7B (OWASP-free) GGUF 변환")
    print("=" * 65)
    if not (ADAPTER_DIR / "adapter_model.safetensors").exists():
        print(f"오류: 어댑터 없음 — {ADAPTER_DIR}/adapter_model.safetensors")
        print(f"  unzip ~/Downloads/adapter_v12_7b.zip -d {ADAPTER_DIR}")
        return
    step1_merge(ADAPTER_DIR, MERGED_DIR)
    step2_convert(MERGED_DIR, F16_GGUF)
    step3_quantize(F16_GGUF, Q4_GGUF)
    step4_register_ollama()
    print("\n완료! ollama run " + OLLAMA_NAME)


if __name__ == "__main__":
    main()
