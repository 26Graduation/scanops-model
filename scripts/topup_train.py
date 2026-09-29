"""v2 어댑터에 gap-fill 데이터 추가 학습 (CORS, Timing, Format String, Supply Chain).

v2 학습 완료 후 실행:
  python scripts/topup_train.py
"""

from __future__ import annotations
import json
import time
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, TaskType, get_peft_model, PeftModel
from transformers import (
    AutoModelForCausalLM, AutoTokenizer,
    DataCollatorForSeq2Seq, Trainer, TrainingArguments,
)

BASE_DIR     = Path(__file__).resolve().parents[1]
GAP_DATA     = BASE_DIR / "data" / "lora_train_gap_fill.jsonl"
ADAPTER_DIR  = BASE_DIR / "models" / "qwen-security-qlora"
BASE_MODEL   = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
DEVICE       = "mps" if torch.backends.mps.is_available() else "cpu"


def load_gap_data() -> Dataset:
    records = []
    with open(GAP_DATA) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    print(f"[topup] gap-fill 데이터: {len(records)}개")
    return Dataset.from_list(records)


def format_qwen(ex: dict) -> dict:
    text = (
        "<|im_start|>system\nYou are a security code analyzer.<|im_end|>\n"
        "<|im_start|>user\n" + ex["prompt"] + "<|im_end|>\n"
        "<|im_start|>assistant\n" + ex["completion"] + "<|im_end|>"
    )
    return {"text": text}


def tokenize(ex: dict, tokenizer, max_len: int = 768) -> dict:
    out = tokenizer(ex["text"], truncation=True, max_length=max_len, padding=False)
    out["labels"] = out["input_ids"].copy()
    return out


def main() -> None:
    print("[topup] v2 어댑터 로드 중...")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    base = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL, dtype=torch.float16,
        device_map=None, trust_remote_code=True,
    ).to(DEVICE)

    model = PeftModel.from_pretrained(base, str(ADAPTER_DIR), is_trainable=True)
    model.print_trainable_parameters()

    ds = load_gap_data()
    ds = ds.map(format_qwen).map(lambda x: tokenize(x, tokenizer), remove_columns=ds.column_names)

    args = TrainingArguments(
        output_dir=str(ADAPTER_DIR),
        num_train_epochs=8,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=4,
        learning_rate=3e-5,
        fp16=False,
        logging_steps=5,
        save_strategy="no",
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=ds,
        data_collator=DataCollatorForSeq2Seq(tokenizer, pad_to_multiple_of=8, return_tensors="pt"),
    )

    t0 = time.time()
    trainer.train()
    elapsed = time.time() - t0

    model.save_pretrained(str(ADAPTER_DIR))
    tokenizer.save_pretrained(str(ADAPTER_DIR))
    print(f"[topup] 완료 — {elapsed/60:.1f}분, 저장: {ADAPTER_DIR}")


if __name__ == "__main__":
    main()
