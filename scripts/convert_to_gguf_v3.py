"""QLoRA v3 GGUF 변환 + Ollama 등록 + HuggingFace Hub 업로드.

단계:
  1. v3 어댑터 병합 → qwen-security-merged-v3/
  2. GGUF F16 변환
  3. Q4_K_M 양자화
  4. 로컬 Ollama 등록 (qwen2.5-coder-security-v3:latest)
  5. HuggingFace Hub 업로드 (SehanKim/qwen2.5-coder-security-v3-gguf)

실행:
  python scripts/convert_to_gguf_v3.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR / "scripts"))

from merge_and_convert import step1_merge, step2_convert, step3_quantize

ADAPTER_DIR = BASE_DIR / "models" / "qwen-security-qlora-v3"
MERGED_DIR  = BASE_DIR / "models" / "qwen-security-merged-v3"
F16_GGUF    = BASE_DIR / "models" / "qwen-security-v3.f16.gguf"
Q4_GGUF     = BASE_DIR / "models" / "qwen-security-v3.Q4_K_M.gguf"
MODELFILE   = BASE_DIR / "models" / "Modelfile_v3"
OLLAMA_NAME = "qwen2.5-coder-security-v3"
HF_REPO     = "SehanKim/qwen2.5-coder-security-v3-gguf"

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


def step4_register_ollama() -> None:
    print(f"[4/5] 로컬 Ollama 등록: {OLLAMA_NAME}")
    MODELFILE.write_text(MODELFILE_CONTENT)
    subprocess.run(["ollama", "create", OLLAMA_NAME, "-f", str(MODELFILE)], check=True)
    print(f"      완료: ollama run {OLLAMA_NAME}")


def step5_upload_hf() -> None:
    print(f"[5/5] HuggingFace Hub 업로드: {HF_REPO}")
    from huggingface_hub import HfApi
    api = HfApi()

    # 레포 생성 (이미 있으면 skip)
    try:
        api.create_repo(repo_id=HF_REPO, repo_type="model", exist_ok=True)
        print(f"      레포 확인: https://huggingface.co/{HF_REPO}")
    except Exception as e:
        print(f"      레포 생성 오류 (무시): {e}")

    print(f"      업로드 중: {Q4_GGUF.name} ({Q4_GGUF.stat().st_size / 1e9:.2f} GB)")
    url = api.upload_file(
        path_or_fileobj=str(Q4_GGUF),
        path_in_repo=f"{Q4_GGUF.name}",
        repo_id=HF_REPO,
        repo_type="model",
        commit_message="Add QLoRA v3 Q4_K_M GGUF (XSS + 28 CWE types, 367 samples)",
    )
    print(f"      업로드 완료: {url}")

    # README 업데이트
    readme = f"""---
language: en
tags:
- security
- vulnerability-detection
- qwen2.5-coder
- qlora
- gguf
---

# ScanOps QLoRA v3 — Security Vulnerability Detection

QLoRA fine-tuned Qwen2.5-Coder-1.5B-Instruct for CVE/CWE vulnerability analysis.

## Model Details
- **Base**: Qwen/Qwen2.5-Coder-1.5B-Instruct
- **Fine-tuning**: QLoRA (r=32, alpha=64, 8 epochs)
- **Training data**: 367 samples, 29 CWE types
- **Quantization**: Q4_K_M (GGUF)
- **Detection rate**: 95%+ (Adaptive 2-stage system)

## Usage with Ollama
```bash
ollama pull hf.co/{HF_REPO}:Q4_K_M
```
"""
    api.upload_file(
        path_or_fileobj=readme.encode(),
        path_in_repo="README.md",
        repo_id=HF_REPO,
        repo_type="model",
        commit_message="Update README for v3",
    )
    print(f"      README 업데이트 완료")


def main() -> None:
    print("=" * 60)
    print("  ScanOps QLoRA v3 GGUF 변환 파이프라인")
    print("=" * 60)

    step1_merge(ADAPTER_DIR, MERGED_DIR)
    step2_convert(MERGED_DIR, F16_GGUF)
    step3_quantize(F16_GGUF, Q4_GGUF)
    step4_register_ollama()
    step5_upload_hf()

    print("\n" + "=" * 60)
    print("  모든 단계 완료!")
    print(f"  로컬:  ollama run {OLLAMA_NAME}")
    print(f"  Hub:   https://huggingface.co/{HF_REPO}")
    print("=" * 60)
    print("\n다음 단계: python scripts/deploy_railway_v3.py")


if __name__ == "__main__":
    main()
