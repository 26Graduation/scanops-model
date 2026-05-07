"""
LoRA Fine-tuning — Gemma 2B (M3 Apple Silicon, MPS backend)
bitsandbytes는 CUDA 전용이므로 사용하지 않음.
float16 + gradient_checkpointing + MPS로 메모리 절감.
"""
import json, time
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, TaskType, get_peft_model
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    DataCollatorForSeq2Seq,
)

# ── 경로 / 설정 ────────────────────────────────────────────────────────────────
BASE  = Path(__file__).resolve().parent.parent
JSONL = BASE / "data"   / "lora_train.jsonl"
SAVE  = BASE / "models" / "tinyllama-security-lora"

# google/gemma-2b requires HF token + accepted license.
# TinyLlama-1.1B is ungated, 2.2GB in fp16 — ideal for M3 8GB.
MODEL_ID    = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
MAX_LEN     = 512
EPOCHS      = 3
BATCH       = 1
GRAD_ACCUM  = 4
LR          = 2e-4
LORA_R      = 8
LORA_ALPHA  = 16
LORA_DROP   = 0.05

# ── 디바이스 ────────────────────────────────────────────────────────────────────
if torch.backends.mps.is_available():
    device = "mps"
elif torch.cuda.is_available():
    device = "cuda"
else:
    device = "cpu"
print(f"Device: {device}")


# ── 데이터 로드 ─────────────────────────────────────────────────────────────────
def load_data():
    records = []
    with open(JSONL, encoding="utf-8") as f:
        for line in f:
            records.append(json.loads(line))
    return Dataset.from_list(records)


# ── 토크나이저 + 전처리 ─────────────────────────────────────────────────────────
def tokenize(tokenizer, example):
    full = example["prompt"] + " " + example["completion"]
    tok  = tokenizer(
        full,
        truncation=True,
        max_length=MAX_LEN,
        padding=False,
    )
    tok["labels"] = tok["input_ids"].copy()
    return tok


def main():
    SAVE.mkdir(parents=True, exist_ok=True)

    # 토크나이저
    print("Loading tokenizer …")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # 데이터셋
    print("Loading dataset …")
    ds = load_data()
    ds = ds.map(lambda ex: tokenize(tokenizer, ex), remove_columns=ds.column_names)
    print(f"  {len(ds)} examples tokenized")

    # 베이스 모델 (float16, MPS)
    print(f"Loading base model: {MODEL_ID} …")
    dtype = torch.float16 if device in ("mps", "cuda") else torch.float32
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        torch_dtype=dtype,
        low_cpu_mem_usage=True,
    )
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()

    # LoRA
    lora_cfg = LoraConfig(
        r=LORA_R,
        lora_alpha=LORA_ALPHA,
        target_modules=["q_proj", "v_proj"],
        lora_dropout=LORA_DROP,
        bias="none",
        task_type=TaskType.CAUSAL_LM,
    )
    model = get_peft_model(model, lora_cfg)
    model.print_trainable_parameters()

    # 학습 인자
    args = TrainingArguments(
        output_dir=str(SAVE),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH,
        gradient_accumulation_steps=GRAD_ACCUM,
        learning_rate=LR,
        fp16=False,
        logging_steps=5,
        save_strategy="epoch",
        report_to="none",
        dataloader_pin_memory=False,
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=ds,
        data_collator=DataCollatorForSeq2Seq(
            tokenizer, model=model, padding=True, pad_to_multiple_of=8
        ),
    )

    # 학습
    print(f"\n학습 시작: epochs={EPOCHS}, batch={BATCH}, grad_accum={GRAD_ACCUM}\n{'─'*50}")
    t0 = time.time()
    result = trainer.train()
    elapsed = round(time.time() - t0, 1)

    # 손실 기록 저장
    log_history = trainer.state.log_history
    loss_log = BASE / "reports" / "lora_train_loss.json"
    loss_log.parent.mkdir(exist_ok=True)
    with open(loss_log, "w") as f:
        json.dump(log_history, f, indent=2)

    # 어댑터 저장
    model.save_pretrained(str(SAVE))
    tokenizer.save_pretrained(str(SAVE))

    final_loss = result.training_loss
    print(f"\n{'─'*50}")
    print(f"학습 완료  |  총 {elapsed}s  |  최종 loss: {final_loss:.4f}")
    print(f"모델 저장: {SAVE}")
    print(f"손실 로그: {loss_log}")


if __name__ == "__main__":
    main()
