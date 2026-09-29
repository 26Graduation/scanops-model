"""LoRA 어댑터 → Ollama 등록 자동화 스크립트.

단계:
  1. LoRA 어댑터 + Qwen 베이스 병합 → merged_model/
  2. merged_model/ → GGUF 변환 (llama-gguf-split 사용)
  3. Q4_K_M 양자화 (선택)
  4. Ollama Modelfile 생성 → ollama create
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

BASE_DIR = Path(__file__).resolve().parents[1]
ADAPTER_DIR = BASE_DIR / "models" / "qwen-security-qlora"
MERGED_DIR  = BASE_DIR / "models" / "qwen-security-merged"
GGUF_PATH   = BASE_DIR / "models" / "qwen-security.Q4_K_M.gguf"
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-1.5B-Instruct"

MODELFILE_TEMPLATE = """\
FROM {gguf_path}

SYSTEM \"\"\"You are a senior security engineer specializing in CVE/CWE vulnerability analysis. Analyze code for security vulnerabilities, identify CVE IDs, CWE IDs, CVSS scores, and provide fix guidance. Always output findings in the specified structured format.\"\"\"

PARAMETER temperature 0.2
PARAMETER top_p 0.9
PARAMETER num_predict 1024
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|endoftext|>"
"""


def merge_adapter(adapter_dir: Path, merged_dir: Path) -> None:
    print(f"[1/4] LoRA 어댑터 병합 중...")
    print(f"      베이스: {BASE_MODEL_ID}")
    print(f"      어댑터: {adapter_dir}")

    tokenizer = AutoTokenizer.from_pretrained(str(adapter_dir), trust_remote_code=True)

    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        dtype=torch.float16,
        trust_remote_code=True,
    )

    model = PeftModel.from_pretrained(base_model, str(adapter_dir))
    print("      가중치 병합 중 (merge_and_unload)...")
    model = model.merge_and_unload()

    merged_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(merged_dir), safe_serialization=True)
    tokenizer.save_pretrained(str(merged_dir))
    print(f"      저장 완료: {merged_dir}")


def convert_to_gguf(merged_dir: Path, gguf_out: Path, quantize: bool = True) -> None:
    print(f"[2/4] GGUF 변환 중...")

    # llama.cpp convert_hf_to_gguf.py 위치 탐색
    llama_cpp_paths = [
        Path("/opt/homebrew/share/llama.cpp"),
        Path("/usr/local/share/llama.cpp"),
        Path("/opt/homebrew/opt/llama.cpp"),
    ]
    convert_script = None
    for p in llama_cpp_paths:
        candidate = p / "convert_hf_to_gguf.py"
        if candidate.exists():
            convert_script = candidate
            break
    if convert_script is None:
        # brew list로 경로 찾기
        result = subprocess.run(
            ["brew", "--prefix", "llama.cpp"], capture_output=True, text=True
        )
        prefix = Path(result.stdout.strip())
        convert_script = prefix / "convert_hf_to_gguf.py"

    if not convert_script.exists():
        print(f"[오류] convert_hf_to_gguf.py 를 찾지 못했습니다.")
        print("       경로를 확인하세요:", convert_script)
        sys.exit(1)

    # f16 GGUF 먼저 생성
    f16_path = gguf_out.with_suffix("").with_suffix("") if quantize else gguf_out
    if quantize:
        f16_path = gguf_out.parent / "qwen-security.f16.gguf"

    subprocess.run(
        [
            sys.executable, str(convert_script),
            str(merged_dir),
            "--outfile", str(f16_path),
            "--outtype", "f16",
        ],
        check=True,
    )
    print(f"      F16 GGUF 생성: {f16_path}")

    if quantize:
        print(f"[3/4] Q4_K_M 양자화 중...")
        llama_quantize = shutil.which("llama-quantize")
        if not llama_quantize:
            result = subprocess.run(
                ["brew", "--prefix", "llama.cpp"], capture_output=True, text=True
            )
            prefix = Path(result.stdout.strip())
            llama_quantize = str(prefix / "bin" / "llama-quantize")

        subprocess.run(
            [llama_quantize, str(f16_path), str(gguf_out), "Q4_K_M"],
            check=True,
        )
        f16_path.unlink(missing_ok=True)
        print(f"      Q4_K_M 완료: {gguf_out} ({gguf_out.stat().st_size / 1e9:.2f} GB)")
    else:
        print(f"[3/4] 양자화 건너뜀")


def register_ollama(gguf_path: Path, model_name: str = "qwen2.5-coder-security") -> None:
    print(f"[4/4] Ollama 등록 중: {model_name}")
    modelfile_path = gguf_path.parent / "Modelfile"
    modelfile_path.write_text(MODELFILE_TEMPLATE.format(gguf_path=gguf_path.resolve()))
    print(f"      Modelfile: {modelfile_path}")

    subprocess.run(
        ["ollama", "create", model_name, "-f", str(modelfile_path)],
        check=True,
    )
    print(f"\n완료! 아래 명령으로 실행하세요:")
    print(f"  ollama run {model_name}")
    print(f"  scanops scan --model {model_name} --code 'your code'")


def main() -> None:
    parser = argparse.ArgumentParser(description="LoRA → Ollama 자동 내보내기")
    parser.add_argument("--adapter-dir", type=Path, default=ADAPTER_DIR)
    parser.add_argument("--merged-dir",  type=Path, default=MERGED_DIR)
    parser.add_argument("--gguf-path",   type=Path, default=GGUF_PATH)
    parser.add_argument("--model-name",  default="qwen2.5-coder-security")
    parser.add_argument("--no-quantize", action="store_true", help="양자화 건너뜀 (속도 우선)")
    parser.add_argument("--skip-merge",  action="store_true", help="이미 merged_model/ 있으면 건너뜀")
    parser.add_argument("--skip-convert",action="store_true", help="이미 GGUF 있으면 건너뜀")
    args = parser.parse_args()

    if not args.skip_merge:
        merge_adapter(args.adapter_dir, args.merged_dir)
    else:
        print("[1/4] 병합 건너뜀 (--skip-merge)")

    if not args.skip_convert:
        convert_to_gguf(args.merged_dir, args.gguf_path, quantize=not args.no_quantize)
    else:
        print("[2-3/4] 변환 건너뜀 (--skip-convert)")

    register_ollama(args.gguf_path, args.model_name)


if __name__ == "__main__":
    main()
