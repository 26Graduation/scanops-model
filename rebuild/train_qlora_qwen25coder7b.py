"""
ScanOps 재구축 — Qwen2.5-Coder-7B-Instruct QLoRA 학습 (RunPod GPU에서 실행)
=============================================================
train_qlora.py(Qwen3.5-9B판)의 베이스 모델 비교용 사본.
MODEL_ID와 어댑터 출력 경로만 다르고, 데이터·하이퍼파라미터는 완전히 동일하게 유지한다
(D1~D6 결정사항 그대로 — 재현율 79.7%/오탐률 15.7%/F1 80.5 기준값과 공정 비교하기 위함).

입력:  rebuild/data/train.jsonl, val.jsonl  (build_dataset.py 산출물, Qwen3.5-9B판과 동일)
출력:  rebuild/out/adapter_qwen25coder7b/  (LoRA 어댑터 — 이후 병합→GGUF→서빙)

흐름:
  1. 베이스 모델을 4bit로 로드 (QLoRA의 'Q')
  2. LoRA 어댑터 부착 — 베이스는 동결, 어댑터만 학습
  3. prompt/completion을 Qwen 채팅 템플릿으로 감쌈
  4. completion 부분만 loss 계산 (프롬프트 베끼기에 학습 낭비 방지)
  5. val loss 감시 — 3회 연속 개선 없으면 조기 종료, 최적 체크포인트 채택

RunPod에서 실행:
  pip install unsloth
  python rebuild/train_qlora_qwen25coder7b.py
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

# ── 결정 사항 (D1~D6, Qwen3.5-9B판과 완전히 동일값 — 베이스 모델만 비교 변수) ──────
MODEL_ID = "unsloth/Qwen2.5-Coder-7B-Instruct"  # unsloth 체크포인트 없으면 "Qwen/Qwen2.5-Coder-7B-Instruct"로 대체
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
# unsloth 사전양자화 체크포인트가 없으면 원본 Qwen 체크포인트를 4bit로 즉석 로드
_FALLBACK_MODEL_ID = "Qwen/Qwen2.5-Coder-7B-Instruct"
try:
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=MODEL_ID,
        max_seq_length=MAX_SEQ_LEN,
        load_in_4bit=True,          # QLoRA: 동결된 베이스를 4bit로 압축 (18GB → ~6GB)
        dtype=None,                 # GPU에 맞춰 자동 (bf16)
    )
except Exception as e:
    print(f"MODEL_ID={MODEL_ID} 로드 실패({e}) → {_FALLBACK_MODEL_ID}로 재시도")
    MODEL_ID = _FALLBACK_MODEL_ID
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=MODEL_ID,
        max_seq_length=MAX_SEQ_LEN,
        load_in_4bit=True,
        dtype=None,
    )
print(f"MODEL_ID(실사용) = {MODEL_ID}")

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

# TRAIN_SPLIT/VAL_SPLIT 환경변수로 데이터셋 선택 (기본 v1, v2는 train_v2/val_v2)
import os
train_ds = load_split(os.environ.get("TRAIN_SPLIT", "train"))
val_ds = load_split(os.environ.get("VAL_SPLIT", "val"))
print(f"train {len(train_ds)} / val {len(val_ds)}")

# ── 4~5. 학습 설정 ───────────────────────────────────────────────────────────
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=train_ds,
    eval_dataset=val_ds,
    args=SFTConfig(
        output_dir=str(OUT_DIR / "checkpoints_qwen25coder7b"),  # 기존 Qwen3.5-9B 체크포인트와 분리
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
# 기존 Qwen3.5-9B 어댑터(out/adapter/)는 비교 기준값이므로 절대 덮어쓰지 않음 — 별도 경로 사용
adapter_dir = OUT_DIR / "adapter_qwen25coder7b"
model.save_pretrained(str(adapter_dir))
tokenizer.save_pretrained(str(adapter_dir))
print(f"LoRA 어댑터 저장 완료 → {adapter_dir}")
print("다음 단계: eval_test_qwen25coder7b.py로 test.jsonl 채점")
