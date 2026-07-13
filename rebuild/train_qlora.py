"""
ScanOps 재구축 — Qwen3.5-9B QLoRA 학습 (RunPod GPU에서 실행)
=============================================================
입력:  rebuild/data/train.jsonl, val.jsonl  (build_dataset.py 산출물)
출력:  rebuild/out/adapter/  (LoRA 어댑터 — 이후 병합→GGUF→서빙)

흐름:
  1. 베이스 모델을 4bit로 로드 (QLoRA의 'Q')
  2. LoRA 어댑터 부착 — 베이스는 동결, 어댑터만 학습
  3. prompt/completion을 Qwen 채팅 템플릿으로 감쌈
  4. completion 부분만 loss 계산 (프롬프트 베끼기에 학습 낭비 방지)
  5. val loss 감시 — 3회 연속 개선 없으면 조기 종료, 최적 체크포인트 채택

RunPod에서 실행:
  pip install unsloth
  python rebuild/train_qlora.py
"""
from __future__ import annotations

# unsloth는 반드시 transformers/trl보다 먼저 import (패치 방식이라 순서 중요)
from unsloth import FastLanguageModel
from unsloth.chat_templates import train_on_responses_only

import json
from pathlib import Path

from datasets import Dataset
from transformers import EarlyStoppingCallback
from trl import SFTConfig, SFTTrainer

# ── 결정 사항 (D1~D6) ────────────────────────────────────────────────────────
MODEL_ID = "unsloth/Qwen3.5-9B"          # D1: instruct판 (HF 확인 완료, -Base 아님)
MAX_SEQ_LEN = 4096                       # D6: 데이터 길이 필터와 동일
LORA_RANK = 16                           # D4: 어댑터 용량 — val loss 보고 조정할 1순위 손잡이
LORA_ALPHA = 32                          # D4: 관례상 rank×2
LEARNING_RATE = 2e-4                     # D5: QLoRA 표준값
MAX_EPOCHS = 3                           # D5: 상한 — early stopping이 보통 먼저 걸림
EARLY_STOP_PATIENCE = 3                  # D5: val loss 3회 연속 미개선 시 중단
BATCH_PER_DEVICE = 2                     # D6: 24GB VRAM 기준
GRAD_ACCUM = 8                           # D6: 유효 배치 = 2×8 = 16
SEED = 42

DATA_DIR = Path(__file__).resolve().parent / "data"
OUT_DIR = Path(__file__).resolve().parent / "out"

# ── 1. 베이스 모델 4bit 로드 ─────────────────────────────────────────────────
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=MODEL_ID,
    max_seq_length=MAX_SEQ_LEN,
    load_in_4bit=True,          # QLoRA: 동결된 베이스를 4bit로 압축 (18GB → ~6GB)
    dtype=None,                 # GPU에 맞춰 자동 (bf16)
)

# ── 2. LoRA 어댑터 부착 ──────────────────────────────────────────────────────
model = FastLanguageModel.get_peft_model(
    model,
    r=LORA_RANK,
    lora_alpha=LORA_ALPHA,
    lora_dropout=0.0,
    # 트랜스포머의 모든 선형층에 어댑터 부착 (attention 4개 + MLP 3개) — 현행 표준
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    use_gradient_checkpointing="unsloth",   # VRAM 절약 (속도 약간 희생)
    random_state=SEED,
)

# ── 3. 데이터 로드 → 채팅 템플릿 적용 ────────────────────────────────────────
def load_split(name: str) -> Dataset:
    rows = [json.loads(l) for l in (DATA_DIR / f"{name}.jsonl").open()]
    def to_text(row):
        messages = [
            {"role": "user", "content": row["prompt"]},
            {"role": "assistant", "content": row["completion"]},
        ]
        return {"text": tokenizer.apply_chat_template(messages, tokenize=False)}
    return Dataset.from_list(rows).map(to_text, remove_columns=["prompt", "completion", "meta"])

train_ds = load_split("train")
val_ds = load_split("val")
print(f"train {len(train_ds)} / val {len(val_ds)}")

# ── 4~5. 학습 설정 ───────────────────────────────────────────────────────────
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=train_ds,
    eval_dataset=val_ds,
    args=SFTConfig(
        output_dir=str(OUT_DIR / "checkpoints"),
        dataset_text_field="text",
        max_seq_length=MAX_SEQ_LEN,
        num_train_epochs=MAX_EPOCHS,
        learning_rate=LEARNING_RATE,
        lr_scheduler_type="cosine",         # 후반으로 갈수록 걸음을 줄여 안정 수렴
        warmup_ratio=0.03,                  # 초반 3%는 작게 시작 (초기 발산 방지)
        per_device_train_batch_size=BATCH_PER_DEVICE,
        per_device_eval_batch_size=BATCH_PER_DEVICE,  # 기본값 8이면 4k토큰×8에서 OOM (1차 시도 크래시 원인)
        gradient_accumulation_steps=GRAD_ACCUM,
        bf16=True,
        logging_steps=20,
        # val loss 감시: 100 스텝마다 평가 → 최적 시점 체크포인트 유지
        eval_strategy="steps",
        eval_steps=100,
        save_strategy="steps",
        save_steps=100,
        save_total_limit=3,
        load_best_model_at_end=True,        # 종료 시 val loss 최저 체크포인트로 복원
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        seed=SEED,
        report_to="none",
    ),
    callbacks=[EarlyStoppingCallback(early_stopping_patience=EARLY_STOP_PATIENCE)],
)

# completion-only loss: assistant 응답 토큰만 채점, 프롬프트 토큰은 loss 제외
trainer = train_on_responses_only(
    trainer,
    instruction_part="<|im_start|>user\n",      # Qwen 채팅 템플릿 구분자 (tokenizer_config에서 확인 완료)
    response_part="<|im_start|>assistant\n",
)

stats = trainer.train()
print(stats)

# ── 어댑터 저장 ──────────────────────────────────────────────────────────────
adapter_dir = OUT_DIR / "adapter"
model.save_pretrained(str(adapter_dir))
tokenizer.save_pretrained(str(adapter_dir))
print(f"LoRA 어댑터 저장 완료 → {adapter_dir}")
print("다음 단계: 어댑터 병합 → GGUF 변환 → test.jsonl 채점")
