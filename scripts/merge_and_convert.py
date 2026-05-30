"""LoRA 병합 + Qwen2 GGUF 변환 스크립트 (llama.cpp 없이 gguf PyPI만 사용).

단계:
  1. PEFT merge_and_unload() → merged_model/
  2. gguf PyPI로 Qwen2 → .gguf (F16)
  3. llama-quantize로 Q4_K_M 양자화
  4. Ollama Modelfile + ollama create
"""

from __future__ import annotations

import argparse
import json
import struct
import subprocess
import sys
from pathlib import Path

import numpy as np
import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

BASE_DIR = Path(__file__).resolve().parents[1]
ADAPTER_DIR = BASE_DIR / "models" / "qwen-security-qlora"
MERGED_DIR  = BASE_DIR / "models" / "qwen-security-merged"
F16_GGUF    = BASE_DIR / "models" / "qwen-security.f16.gguf"
Q4_GGUF     = BASE_DIR / "models" / "qwen-security.Q4_K_M.gguf"
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-1.5B-Instruct"

MODELFILE_TMPL = """\
FROM {gguf_path}

SYSTEM \"\"\"You are a senior security engineer specializing in CVE/CWE vulnerability analysis. \
Analyze code for security vulnerabilities with CVE IDs, CWE IDs, CVSS scores, and fix guidance. \
Always output findings in the structured VULNERABILITY/CVE/CWE/CVSS/LOCATION/ATTACK/FIX format.\"\"\"

PARAMETER temperature 0.2
PARAMETER top_p 0.9
PARAMETER num_predict 1024
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|endoftext|>"
"""


# ── 1단계: LoRA 병합 ────────────────────────────────────────────────────────────

def step1_merge(adapter_dir: Path, merged_dir: Path, skip: bool = False) -> None:
    if skip and merged_dir.exists() and any(merged_dir.glob("*.safetensors")):
        print("[1/4] 병합 건너뜀 (이미 존재)")
        return

    print(f"[1/4] LoRA 어댑터 병합 중...")
    print(f"      베이스: {BASE_MODEL_ID}")
    print(f"      어댑터: {adapter_dir}")

    tokenizer = AutoTokenizer.from_pretrained(str(adapter_dir), trust_remote_code=True)
    base = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID, dtype=torch.float16, trust_remote_code=True
    )
    model = PeftModel.from_pretrained(base, str(adapter_dir))
    print("      merge_and_unload() 실행 중...")
    model = model.merge_and_unload()

    merged_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(merged_dir), safe_serialization=True)
    tokenizer.save_pretrained(str(merged_dir))
    print(f"      저장 완료: {merged_dir}")


# ── 2단계: Qwen2 → GGUF (F16) ──────────────────────────────────────────────────

def step2_convert(merged_dir: Path, gguf_out: Path, skip: bool = False) -> None:
    if skip and gguf_out.exists():
        print(f"[2/4] 변환 건너뜀 (이미 존재: {gguf_out})")
        return

    print(f"[2/4] Qwen2 → GGUF (F16) 변환 중...")

    import gguf as gguf_pkg
    from gguf import GGUFWriter, MODEL_ARCH, get_tensor_name_map

    # config 읽기
    config_path = merged_dir / "config.json"
    with open(config_path) as f:
        cfg = json.load(f)

    n_layers      = cfg["num_hidden_layers"]
    hidden_size   = cfg["hidden_size"]
    ffn_size      = cfg["intermediate_size"]
    n_heads       = cfg["num_attention_heads"]
    n_kv_heads    = cfg.get("num_key_value_heads", n_heads)
    vocab_size    = cfg["vocab_size"]
    ctx_len       = cfg.get("max_position_embeddings", 32768)
    rope_theta    = float(cfg.get("rope_theta", 1_000_000.0))
    rms_eps       = float(cfg.get("rms_norm_eps", 1e-6))
    head_dim      = hidden_size // n_heads

    print(f"      layers={n_layers}, hidden={hidden_size}, heads={n_heads}/{n_kv_heads}, vocab={vocab_size}")

    writer = GGUFWriter(str(gguf_out), "qwen2")

    # ── 메타데이터 ──
    writer.add_string("general.name", "qwen2.5-coder-security-qlora")
    writer.add_string("general.description", "Qwen2.5-Coder-1.5B fine-tuned with QLoRA for security vulnerability analysis")
    writer.add_uint32("qwen2.context_length", ctx_len)
    writer.add_uint32("qwen2.embedding_length", hidden_size)
    writer.add_uint32("qwen2.block_count", n_layers)
    writer.add_uint32("qwen2.feed_forward_length", ffn_size)
    writer.add_uint32("qwen2.attention.head_count", n_heads)
    writer.add_uint32("qwen2.attention.head_count_kv", n_kv_heads)
    writer.add_float32("qwen2.attention.layer_norm_rms_epsilon", rms_eps)
    writer.add_uint32("qwen2.rope.dimension_count", head_dim)
    writer.add_float32("qwen2.rope.freq_base", rope_theta)
    writer.add_uint32("general.file_type", 1)  # F16

    # ── 토크나이저 ──
    tok_path = merged_dir / "tokenizer.json"
    with open(tok_path) as f:
        tok_data = json.load(f)

    vocab_dict = tok_data["model"]["vocab"]
    merges_list = tok_data["model"].get("merges", [])
    tokens = [""] * vocab_size
    scores = [0.0] * vocab_size
    toktypes = [1] * vocab_size

    for tok, idx in vocab_dict.items():
        if idx < vocab_size:
            tokens[idx] = tok
            scores[idx] = 0.0
            toktypes[idx] = 1

    # 특수 토큰 타입 표시
    special_ids = set()
    if "added_tokens" in tok_data:
        for at in tok_data["added_tokens"]:
            if at.get("special", False) and at["id"] < vocab_size:
                special_ids.add(at["id"])
                toktypes[at["id"]] = 3  # CONTROL

    # merges: [[a,b], ...] → ["a b", ...] (GGUF string array 형식)
    if merges_list and isinstance(merges_list[0], list):
        merges_list = [" ".join(pair) for pair in merges_list]

    writer.add_string("tokenizer.ggml.model", "gpt2")
    writer.add_string("tokenizer.ggml.pre", "qwen2")
    writer.add_array("tokenizer.ggml.tokens", tokens)
    writer.add_array("tokenizer.ggml.scores", scores)
    writer.add_array("tokenizer.ggml.token_type", toktypes)
    if merges_list:
        writer.add_array("tokenizer.ggml.merges", merges_list)

    # BOS/EOS 토큰
    tok_cfg_path = merged_dir / "tokenizer_config.json"
    with open(tok_cfg_path) as f:
        tok_cfg = json.load(f)
    bos_id = tok_cfg.get("bos_token_id", 151643)
    eos_id = tok_cfg.get("eos_token_id", 151645)
    writer.add_uint32("tokenizer.ggml.bos_token_id", bos_id if bos_id else 151643)
    writer.add_uint32("tokenizer.ggml.eos_token_id", eos_id if isinstance(eos_id, int) else 151645)
    writer.add_uint32("tokenizer.ggml.padding_token_id", 151643)
    writer.add_bool("tokenizer.ggml.add_bos_token", False)
    writer.add_bool("tokenizer.ggml.add_eos_token", False)

    # ── 텐서 로드 및 쓰기 ──
    print("      텐서 로드 중 (safetensors)...")
    from safetensors.torch import load_file
    import glob

    shard_files = sorted(glob.glob(str(merged_dir / "model*.safetensors")))
    if not shard_files:
        shard_files = sorted(glob.glob(str(merged_dir / "*.safetensors")))

    tensors: dict[str, np.ndarray] = {}
    for sf in shard_files:
        st = load_file(sf)
        for k, v in st.items():
            tensors[k] = v.to(torch.float16).numpy()
        print(f"        로드: {Path(sf).name} ({len(st)} 텐서)")

    # HuggingFace → GGUF 텐서 이름 매핑 (Qwen2)
    def hf_to_gguf_name(hf_name: str) -> str | None:
        if hf_name == "model.embed_tokens.weight":
            return "token_embd.weight"
        if hf_name == "model.norm.weight":
            return "output_norm.weight"
        if hf_name == "lm_head.weight":
            return "output.weight"

        import re
        m = re.match(r"model\.layers\.(\d+)\.(.*)", hf_name)
        if not m:
            return None
        layer, rest = int(m.group(1)), m.group(2)

        layer_map = {
            "input_layernorm.weight":           "attn_norm.weight",
            "post_attention_layernorm.weight":  "ffn_norm.weight",
            "self_attn.q_proj.weight":          "attn_q.weight",
            "self_attn.q_proj.bias":            "attn_q.bias",
            "self_attn.k_proj.weight":          "attn_k.weight",
            "self_attn.k_proj.bias":            "attn_k.bias",
            "self_attn.v_proj.weight":          "attn_v.weight",
            "self_attn.v_proj.bias":            "attn_v.bias",
            "self_attn.o_proj.weight":          "attn_output.weight",
            "mlp.gate_proj.weight":             "ffn_gate.weight",
            "mlp.up_proj.weight":               "ffn_up.weight",
            "mlp.down_proj.weight":             "ffn_down.weight",
        }
        mapped = layer_map.get(rest)
        if mapped:
            return f"blk.{layer}.{mapped}"
        return None

    # F32로 유지해야 하는 텐서 패턴 (RMSNorm weights, biases)
    F32_SUFFIXES = (
        "attn_norm.weight",   # input_layernorm
        "ffn_norm.weight",    # post_attention_layernorm
        "output_norm.weight", # model.norm
        "attn_q.bias",
        "attn_k.bias",
        "attn_v.bias",
    )

    print(f"      텐서 쓰기 중 ({len(tensors)}개)...")
    written = 0
    skipped = []
    for hf_name, arr in tensors.items():
        gguf_name = hf_to_gguf_name(hf_name)
        if gguf_name is None:
            skipped.append(hf_name)
            continue
        # RMSNorm과 bias는 F32, 나머지는 F16
        if any(gguf_name.endswith(s) for s in F32_SUFFIXES):
            out_arr = arr.astype(np.float32)
        else:
            out_arr = arr  # already float16
        writer.add_tensor(gguf_name, out_arr)
        written += 1

    if skipped:
        print(f"      건너뜀 {len(skipped)}개: {skipped[:3]}{'...' if len(skipped)>3 else ''}")
    print(f"      쓰기 완료: {written}개 텐서")

    writer.write_header_to_file()
    writer.write_kv_data_to_file()
    writer.write_tensors_to_file()
    writer.close()

    size_gb = gguf_out.stat().st_size / 1e9
    print(f"      F16 GGUF 저장: {gguf_out} ({size_gb:.2f} GB)")


# ── 3단계: Q4_K_M 양자화 ───────────────────────────────────────────────────────

def step3_quantize(f16_path: Path, q4_path: Path, skip: bool = False) -> None:
    if skip and q4_path.exists():
        print(f"[3/4] 양자화 건너뜀 (이미 존재)")
        return

    print(f"[3/4] Q4_K_M 양자화 중...")
    llama_quantize = "/opt/homebrew/bin/llama-quantize"
    subprocess.run([llama_quantize, str(f16_path), str(q4_path), "Q4_K_M"], check=True)
    size_gb = q4_path.stat().st_size / 1e9
    print(f"      Q4_K_M 완료: {q4_path} ({size_gb:.2f} GB)")
    f16_path.unlink(missing_ok=True)
    print(f"      F16 임시 파일 삭제")


# ── 4단계: Ollama 등록 ─────────────────────────────────────────────────────────

def step4_ollama(gguf_path: Path, model_name: str) -> None:
    print(f"[4/4] Ollama 등록: {model_name}")
    modelfile = gguf_path.parent / "Modelfile"
    modelfile.write_text(MODELFILE_TMPL.format(gguf_path=gguf_path.resolve()))

    subprocess.run(["ollama", "create", model_name, "-f", str(modelfile)], check=True)
    print(f"\n✓ 완료! 실행 방법:")
    print(f"  ollama run {model_name}")
    print(f"  scanops scan --model {model_name} -c 'import pickle; pickle.loads(data)'")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--adapter-dir",  type=Path, default=ADAPTER_DIR)
    p.add_argument("--merged-dir",   type=Path, default=MERGED_DIR)
    p.add_argument("--f16-gguf",     type=Path, default=F16_GGUF)
    p.add_argument("--q4-gguf",      type=Path, default=Q4_GGUF)
    p.add_argument("--model-name",   default="qwen2.5-coder-security")
    p.add_argument("--skip-merge",   action="store_true")
    p.add_argument("--skip-convert", action="store_true")
    p.add_argument("--skip-quantize",action="store_true")
    p.add_argument("--no-quantize",  action="store_true", help="양자화 없이 F16으로 Ollama 등록")
    args = p.parse_args()

    step1_merge(args.adapter_dir, args.merged_dir, skip=args.skip_merge)
    step2_convert(args.merged_dir, args.f16_gguf, skip=args.skip_convert)

    if args.no_quantize:
        step4_ollama(args.f16_gguf, args.model_name)
    else:
        step3_quantize(args.f16_gguf, args.q4_gguf, skip=args.skip_quantize)
        step4_ollama(args.q4_gguf, args.model_name)


if __name__ == "__main__":
    main()
