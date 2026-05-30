"""QLoRA v3 토프업 — lora_train_v4_additional.jsonl (76샘플) 추가 학습.

기존 v2 어댑터(qwen-security-qlora)를 로드해 XSS·CWE 보강 데이터로 계속 학습.
저장: models/qwen-security-qlora-v3/

실행:
  cd /Users/kimsehan/Desktop/scanops/scanops-model
  source .venv/bin/activate
  python scripts/topup_v3.py
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import torch
from datasets import Dataset
from peft import PeftModel
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    DataCollatorForSeq2Seq,
    Trainer,
    TrainingArguments,
)

BASE_DIR    = Path(__file__).resolve().parents[1]
TRAIN_DATA  = BASE_DIR / "data"  / "lora_train_v4_additional.jsonl"
SRC_ADAPTER = BASE_DIR / "models" / "qwen-security-qlora"
OUT_ADAPTER = BASE_DIR / "models" / "qwen-security-qlora-v3"
BASE_MODEL  = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
DEVICE      = "mps" if torch.backends.mps.is_available() else "cpu"

EPOCHS     = 8
BATCH      = 1
GRAD_ACCUM = 4
LR         = 2e-5   # v2보다 약간 낮춰 catastrophic forgetting 방지
MAX_LEN    = 768


def load_data() -> Dataset:
    records = []
    with open(TRAIN_DATA) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    print(f"[v3] 추가 학습 데이터: {len(records)}개")
    return Dataset.from_list(records)


def format_qwen(ex: dict) -> dict:
    text = (
        "<|im_start|>system\nYou are a security code analyzer.<|im_end|>\n"
        "<|im_start|>user\n" + ex["prompt"] + "<|im_end|>\n"
        "<|im_start|>assistant\n" + ex["completion"] + "<|im_end|>"
    )
    return {"text": text}


def tokenize(ex: dict, tokenizer) -> dict:
    out = tokenizer(ex["text"], truncation=True, max_length=MAX_LEN, padding=False)
    out["labels"] = out["input_ids"].copy()
    return out


def main() -> None:
    print("=" * 60)
    print("  ScanOps QLoRA v3 토프업 학습")
    print(f"  데이터: {TRAIN_DATA.name}  ({TRAIN_DATA.stat().st_size // 1024}KB)")
    print(f"  src 어댑터: {SRC_ADAPTER}")
    print(f"  저장 경로:  {OUT_ADAPTER}")
    print("=" * 60)

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    base = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        torch_dtype=torch.float16,
        device_map=None,
        trust_remote_code=True,
    ).to(DEVICE)

    model = PeftModel.from_pretrained(base, str(SRC_ADAPTER), is_trainable=True)
    model.print_trainable_parameters()

    ds = load_data()
    ds = ds.map(format_qwen)
    ds = ds.map(lambda x: tokenize(x, tokenizer), remove_columns=ds.column_names)
    print(f"[v3] 토크나이즈 완료: {len(ds)}개 (max_len={MAX_LEN})")

    OUT_ADAPTER.mkdir(parents=True, exist_ok=True)

    args = TrainingArguments(
        output_dir=str(OUT_ADAPTER),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH,
        gradient_accumulation_steps=GRAD_ACCUM,
        learning_rate=LR,
        fp16=False,
        bf16=False,
        logging_steps=5,
        save_strategy="no",
        report_to="none",
        dataloader_pin_memory=False,
        optim="adamw_torch",
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=ds,
        data_collator=DataCollatorForSeq2Seq(
            tokenizer, pad_to_multiple_of=8, return_tensors="pt"
        ),
    )

    t0 = time.time()
    result = trainer.train()
    elapsed = time.time() - t0

    model.save_pretrained(str(OUT_ADAPTER))
    tokenizer.save_pretrained(str(OUT_ADAPTER))

    # 손실 로그 저장
    log_path = OUT_ADAPTER / "train_loss_v3.json"
    with open(log_path, "w") as f:
        json.dump(trainer.state.log_history, f, indent=2)

    print("=" * 60)
    print(f"  완료! {elapsed / 60:.1f}분  |  final loss: {result.training_loss:.4f}")
    print(f"  저장: {OUT_ADAPTER}")
    print("=" * 60)
    print("\n다음 단계:")
    print("  python scripts/convert_to_gguf_v3.py")


if __name__ == "__main__":
    main()
