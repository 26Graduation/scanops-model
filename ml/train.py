"""
ScanOps 보안 모델 학습 — QLoRA 지도 파인튜닝 (단일 진입점)
================================================================
이 파일이 "어디서 학습하는가"에 대한 단일 정답이다. 다른 ML 엔지니어가
이 파일 하나만 읽으면 학습 방법 전체를 파악할 수 있도록 작성했다.

방법(method):
  1. 베이스 모델: Qwen2.5-Coder-1.5B-Instruct (사전학습된 코드 특화 트랜스포머)
  2. QLoRA: 베이스 가중치는 4bit로 동결(CUDA) 또는 fp16 동결(MPS/CPU)하고,
     어텐션 투영(q/k/v/o)에 저랭크 어댑터(LoRA, r=32)만 학습한다.
     → 전체 1.55B 중 8.7M(0.56%)만 업데이트 → 단일 GPU/Mac에서 학습 가능.
  3. 목적함수: assistant 응답 토큰에 대한 교차 엔트로피 손실.
  4. 최적화: AdamW + cosine LR 스케줄 + 역전파(backpropagation).
  5. 과적합 방지: LoRA dropout(0.05), train/eval 분할 + best-checkpoint 선택,
     낮은 LoRA 랭크(용량 제한), 데이터 클래스 균형(config.py 교훈 참조).

실행:
  # 클라우드 GPU(권장, CUDA 4bit QLoRA — 5~10분):
  python -m ml.train --tag v8 --epochs 3
  # 로컬 Mac(MPS fp16 폴백 — 1~2시간):
  python -m ml.train --tag v8 --epochs 3

환경 자동 감지: CUDA → 4bit QLoRA, MPS(Mac) → fp16, CPU → fp32.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig as PeftLoraConfig, TaskType, get_peft_model
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    DataCollatorForSeq2Seq,
    Trainer,
    TrainingArguments,
)

from ml.config import CONFIG, Config


# ── 1. 디바이스/양자화 환경 감지 ─────────────────────────────────────────────
def detect_device() -> tuple[str, bool]:
    """returns (device, use_4bit). 4bit QLoRA는 CUDA에서만 가능."""
    if torch.cuda.is_available():
        return "cuda", CONFIG.train.use_4bit_on_cuda
    if torch.backends.mps.is_available():
        return "mps", False        # Apple Silicon: bitsandbytes 미지원 → fp16
    return "cpu", False


# ── 2. 데이터 로드 + ChatML 포맷팅 ───────────────────────────────────────────
def load_dataset(train_file: Path) -> Dataset:
    rows = []
    with open(train_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    print(f"[data] {len(rows)}개 예시 로드 ({train_file.name})")
    n_none = sum(1 for r in rows if r["completion"].split("\n")[0].upper().startswith("VULNERABILITY: NONE"))
    print(f"[data] 안전(NONE) 비율 {100*n_none/len(rows):.1f}%  (클래스 균형 확인)")
    return Dataset.from_list(rows)


def format_chatml(example: dict) -> dict:
    """Qwen ChatML 포맷. prompt=user, completion=assistant."""
    text = (
        "<|im_start|>system\nYou are a security code analyzer.<|im_end|>\n"
        "<|im_start|>user\n" + example["prompt"] + "<|im_end|>\n"
        "<|im_start|>assistant\n" + example["completion"] + "<|im_end|>"
    )
    return {"text": text}


def tokenize(example: dict, tokenizer, max_len: int) -> dict:
    out = tokenizer(example["text"], truncation=True, max_length=max_len, padding=False)
    out["labels"] = out["input_ids"].copy()   # causal LM: 입력=정답(shift는 모델 내부)
    return out


# ── 3. 모델 로드 (4bit QLoRA 또는 fp16 폴백) ─────────────────────────────────
def load_model(cfg: Config, device: str, use_4bit: bool):
    tokenizer = AutoTokenizer.from_pretrained(cfg.model.base_model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    if use_4bit:
        from transformers import BitsAndBytesConfig
        bnb = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
        model = AutoModelForCausalLM.from_pretrained(
            cfg.model.base_model_id, quantization_config=bnb,
            device_map="auto", trust_remote_code=True,
        )
        from peft import prepare_model_for_kbit_training
        model = prepare_model_for_kbit_training(model)
        print("[model] 4bit QLoRA (CUDA/bitsandbytes nf4 + double-quant)")
    else:
        dtype = torch.float16 if device == "mps" else torch.float32
        model = AutoModelForCausalLM.from_pretrained(
            cfg.model.base_model_id, dtype=dtype, trust_remote_code=True,
        ).to(device)
        print(f"[model] {dtype} 폴백 ({device}) — 4bit 미사용")

    lora = PeftLoraConfig(
        r=cfg.lora.r, lora_alpha=cfg.lora.alpha, lora_dropout=cfg.lora.dropout,
        target_modules=list(cfg.lora.target_modules), task_type=TaskType.CAUSAL_LM,
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()
    return model, tokenizer


# ── 4. 학습 ──────────────────────────────────────────────────────────────────
def train(cfg: Config) -> None:
    device, use_4bit = detect_device()
    print(f"[env] device={device}, 4bit_QLoRA={use_4bit}")
    t = cfg.train

    ds = load_dataset(cfg.data.train_file)
    split = ds.train_test_split(test_size=t.eval_ratio, seed=t.seed)

    model, tokenizer = load_model(cfg, device, use_4bit)

    train_ds = split["train"].map(format_chatml).map(
        lambda x: tokenize(x, tokenizer, cfg.model.max_seq_len),
        remove_columns=split["train"].column_names + ["text"],
    )
    eval_ds = split["test"].map(format_chatml).map(
        lambda x: tokenize(x, tokenizer, cfg.model.max_seq_len),
        remove_columns=split["test"].column_names + ["text"],
    )

    args = TrainingArguments(
        output_dir=str(cfg.adapter_dir),
        num_train_epochs=t.epochs,
        per_device_train_batch_size=t.batch_size,
        per_device_eval_batch_size=t.batch_size,
        gradient_accumulation_steps=t.grad_accum,
        learning_rate=t.learning_rate,
        weight_decay=t.weight_decay,
        warmup_ratio=t.warmup_ratio,
        lr_scheduler_type="cosine",
        fp16=(device == "cuda"),
        logging_steps=10,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        report_to="none",
    )
    trainer = Trainer(
        model=model, args=args, train_dataset=train_ds, eval_dataset=eval_ds,
        data_collator=DataCollatorForSeq2Seq(tokenizer, pad_to_multiple_of=8, return_tensors="pt"),
    )

    t0 = time.time()
    trainer.train()
    mins = (time.time() - t0) / 60

    cfg.adapter_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(cfg.adapter_dir))
    tokenizer.save_pretrained(str(cfg.adapter_dir))

    # 학습곡선 로그 저장 (visualize.py 가 사용)
    log = [{"step": e["step"], "loss": e.get("loss"), "eval_loss": e.get("eval_loss")}
           for e in trainer.state.log_history if "loss" in e or "eval_loss" in e]
    cfg.loss_log.write_text(json.dumps(log, indent=2))
    print(f"[done] {mins:.1f}분, 어댑터 저장: {cfg.adapter_dir}")
    print(f"[done] 학습곡선 로그: {cfg.loss_log}")


def main():
    ap = argparse.ArgumentParser(description="ScanOps QLoRA 파인튜닝")
    ap.add_argument("--tag", default=CONFIG.tag, help="산출물 태그 (예: v8)")
    ap.add_argument("--epochs", type=int, default=CONFIG.train.epochs)
    ap.add_argument("--lora-r", type=int, default=CONFIG.lora.r)
    ap.add_argument("--data", type=Path, default=CONFIG.data.train_file)
    args = ap.parse_args()

    CONFIG.tag = args.tag
    CONFIG.train.epochs = args.epochs
    CONFIG.lora.r = args.lora_r
    CONFIG.lora.alpha = args.lora_r * 2
    CONFIG.data.train_file = args.data
    train(CONFIG)


if __name__ == "__main__":
    main()
