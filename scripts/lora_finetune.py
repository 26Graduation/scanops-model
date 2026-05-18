"""
LoRA Fine-tuning — Gemma-2 2B IT (M3 Apple Silicon, MPS backend)
기존 TinyLlama 1.1B에서 google/gemma-2-2b-it (2B, 훨씬 강력)로 업그레이드.

모델 선택 이유:
  - gemma-2-2b-it: Gemma 2 아키텍처, instruction-tuned, 보안 추론 품질↑
  - TinyLlama 대비 동일 메모리에서 탐지율 대폭 향상 기대
  - M3 8GB: float16 + LoRA → ~5~6GB 사용, 실행 가능

학습 데이터: data/lora_train_v2.jsonl (200+개, 19개 CWE)
"""
import json
import time
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, TaskType, get_peft_model
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    DataCollatorForSeq2Seq,
    Trainer,
    TrainingArguments,
)

BASE     = Path(__file__).resolve().parent.parent
JSONL    = BASE / "data" / "lora_train_v2.jsonl"
SAVE     = BASE / "models" / "gemma2-security-lora"

# Gemma-2 2B IT — ungated 버전 (HuggingFace Hub 무료 접근 가능)
# fallback: TinyLlama (JSONL v1 50개 데이터용)
MODEL_ID    = "google/gemma-2-2b-it"
FALLBACK_ID = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"

MAX_LEN    = 768
EPOCHS     = 5
BATCH      = 1
GRAD_ACCUM = 8
LR         = 1e-4
LORA_R     = 16
LORA_ALPHA = 32
LORA_DROP  = 0.05

# ── 디바이스 ────────────────────────────────────────────────────────────────────
if torch.backends.mps.is_available():
    device = "mps"
elif torch.cuda.is_available():
    device = "cuda"
else:
    device = "cpu"
print(f"Device: {device}")


# ── 데이터 로드 ─────────────────────────────────────────────────────────────────
def load_data(path: Path) -> Dataset:
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    print(f"  학습 데이터: {len(records)}개 로드")
    return Dataset.from_list(records)


# ── Gemma-2 chat format으로 래핑 ────────────────────────────────────────────────
def format_gemma2(example: dict) -> dict:
    """
    Gemma-2 IT 형식: <start_of_turn>user ... <end_of_turn><start_of_turn>model ... <end_of_turn>
    일반 causal LM 방식으로 prompt+completion을 하나로 이어 붙임.
    """
    text = (
        "<start_of_turn>user\n"
        + example["prompt"]
        + "<end_of_turn>\n"
        "<start_of_turn>model\n"
        + example["completion"]
        + "<end_of_turn>"
    )
    return {"text": text}


def tokenize(tokenizer, example: dict, max_len: int) -> dict:
    tok = tokenizer(
        example["text"],
        truncation=True,
        max_length=max_len,
        padding=False,
    )
    tok["labels"] = tok["input_ids"].copy()
    return tok


def main(model_id: str = MODEL_ID, jsonl: Path = JSONL) -> None:
    if not jsonl.exists():
        # v2 없으면 v1 fallback
        jsonl_v1 = BASE / "data" / "lora_train.jsonl"
        if jsonl_v1.exists():
            print(f"[경고] {jsonl} 없음 → {jsonl_v1} 사용")
            jsonl = jsonl_v1
        else:
            raise FileNotFoundError(f"학습 데이터 없음: {jsonl}")

    SAVE.mkdir(parents=True, exist_ok=True)

    # ── 토크나이저 ──────────────────────────────────────────────────────────────
    print(f"Loading tokenizer: {model_id} …")
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_id)
    except OSError:
        print(f"[경고] {model_id} 다운로드 실패 → fallback: {FALLBACK_ID}")
        model_id  = FALLBACK_ID
        tokenizer = AutoTokenizer.from_pretrained(model_id)

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # ── 데이터셋 ────────────────────────────────────────────────────────────────
    print("Preparing dataset …")
    ds = load_data(jsonl)

    # Gemma-2 IT chat format 적용
    if "gemma-2" in model_id.lower() or "gemma2" in model_id.lower():
        ds = ds.map(format_gemma2, remove_columns=[c for c in ds.column_names if c != "text"])
        ds = ds.map(
            lambda ex: tokenize(tokenizer, ex, MAX_LEN),
            remove_columns=ds.column_names,
        )
    else:
        # TinyLlama fallback: 기존 방식
        def tokenize_plain(example):
            full = example["prompt"] + " " + example["completion"]
            tok  = tokenizer(full, truncation=True, max_length=MAX_LEN, padding=False)
            tok["labels"] = tok["input_ids"].copy()
            return tok
        ds = ds.map(tokenize_plain, remove_columns=ds.column_names)

    print(f"  {len(ds)} examples tokenized  (max_len={MAX_LEN})")

    # ── 베이스 모델 ─────────────────────────────────────────────────────────────
    print(f"Loading base model: {model_id} …")
    dtype = torch.float16 if device in ("mps", "cuda") else torch.float32
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=dtype,
        low_cpu_mem_usage=True,
    )
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()

    # ── LoRA 설정 ───────────────────────────────────────────────────────────────
    # Gemma-2는 q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj
    target_modules = (
        ["q_proj", "k_proj", "v_proj", "o_proj"]
        if "gemma" in model_id.lower()
        else ["q_proj", "v_proj"]
    )
    lora_cfg = LoraConfig(
        r=LORA_R,
        lora_alpha=LORA_ALPHA,
        target_modules=target_modules,
        lora_dropout=LORA_DROP,
        bias="none",
        task_type=TaskType.CAUSAL_LM,
    )
    model = get_peft_model(model, lora_cfg)
    model.print_trainable_parameters()

    # ── 학습 인자 ───────────────────────────────────────────────────────────────
    args = TrainingArguments(
        output_dir=str(SAVE),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH,
        gradient_accumulation_steps=GRAD_ACCUM,
        learning_rate=LR,
        fp16=False,
        bf16=False,
        logging_steps=10,
        save_strategy="epoch",
        report_to="none",
        dataloader_pin_memory=False,
        optim="adamw_torch",
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=ds,
        data_collator=DataCollatorForSeq2Seq(
            tokenizer, model=model, padding=True, pad_to_multiple_of=8
        ),
    )

    # ── 학습 ────────────────────────────────────────────────────────────────────
    print(f"\n학습 시작: {model_id}")
    print(f"  epochs={EPOCHS}, batch={BATCH}, grad_accum={GRAD_ACCUM}, lr={LR}")
    print(f"  LoRA r={LORA_R}, alpha={LORA_ALPHA}, targets={target_modules}")
    print("─" * 55)

    t0     = time.time()
    result = trainer.train()
    elapsed = round(time.time() - t0, 1)

    # ── 결과 저장 ───────────────────────────────────────────────────────────────
    log_path = BASE / "reports" / "lora_train_loss.json"
    log_path.parent.mkdir(exist_ok=True)
    with open(log_path, "w") as f:
        json.dump(trainer.state.log_history, f, indent=2)

    model.save_pretrained(str(SAVE))
    tokenizer.save_pretrained(str(SAVE))

    print("─" * 55)
    print(f"학습 완료  |  {elapsed}s  |  loss: {result.training_loss:.4f}")
    print(f"모델 저장: {SAVE}")
    print(f"손실 로그: {log_path}")
    print(f"\n다음 단계: python scripts/benchmark_local.py --model lora")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=MODEL_ID, help="HuggingFace 모델 ID")
    parser.add_argument("--data",  default=str(JSONL), help="학습 JSONL 경로")
    parser.add_argument("--fallback", action="store_true",
                        help=f"TinyLlama fallback ({FALLBACK_ID}) 강제 사용")
    args = parser.parse_args()

    mid  = FALLBACK_ID if args.fallback else args.model
    main(model_id=mid, jsonl=Path(args.data))
