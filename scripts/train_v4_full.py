"""
ScanOps QLoRA v4 — 전체(scratch) 재훈련
=========================================
기존 어댑터 로드 없이 처음부터 학습 (Catastrophic Forgetting 방지).
데이터: data/lora_train_v4_combined.jsonl (1,000개+)
저장:   models/qwen-security-qlora-v4/

개선 사항 vs v3:
  • scratch 학습 — 이전 어댑터 편향 없음
  • CVSS 필드 포함 새 포맷 (VULNERABILITY/SEVERITY/CVSS/ATTACK/FIX)
  • CWE Top-25 전수 커버 1,000 샘플
  • LoRA rank 32, alpha 64, 더 넓은 타겟 모듈
  • LR Warmup 100 steps, Cosine schedule
  • 에포크 4 (데이터가 많아 과적합 방지)

실행:
  cd /Users/kimsehan/Desktop/scanops/scanops-model
  source .venv/bin/activate
  python scripts/train_v4_full.py
"""

from __future__ import annotations

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
    get_cosine_schedule_with_warmup,
)

# ── 경로 설정 ─────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parents[1]
TRAIN_DATA = BASE_DIR / "data"  / "lora_train_v4_combined.jsonl"
OUT_DIR    = BASE_DIR / "models" / "qwen-security-qlora-v4"
BASE_MODEL = "Qwen/Qwen2.5-Coder-1.5B-Instruct"

# ── 하이퍼파라미터 ─────────────────────────────────────────────────────────────
EPOCHS      = 3         # 속도 최적화: 4→3 (M3 기준 ~18분)
BATCH       = 1
GRAD_ACCUM  = 8         # 효과적 배치 = 8
LR          = 3e-4      # LoRA 표준 학습률
WARMUP_STEPS = 80
MAX_LEN     = 512       # 속도 최적화: 768→512 (메모리·속도 개선)

# LoRA 설정 — v4: rank=32, alpha=64, q/k/v/o + gate/up/down
LORA_R      = 32
LORA_ALPHA  = 64
LORA_DROPOUT = 0.05
LORA_TARGETS = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]

DEVICE = "mps" if torch.backends.mps.is_available() else "cpu"


# ── 시스템 프롬프트 ─────────────────────────────────────────────────────────────
SYSTEM = (
    "You are a security code analyzer. "
    "Always respond in EXACTLY this format, starting with VULNERABILITY on the first line:\n"
    "VULNERABILITY: [vulnerability name with CWE ID]\n"
    "SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]\n"
    "CVSS: [CVSS base score, e.g. 9.8]\n"
    "ATTACK: [한 문장으로 공격 시나리오 설명 (반드시 한국어)]\n"
    "FIX: [수정된 코드. 코드가 없으면 한국어로 해결 방법 설명]"
)


def load_data() -> Dataset:
    records = []
    with open(TRAIN_DATA, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    print(f"[v4] 학습 데이터: {len(records):,}개")
    return Dataset.from_list(records)


def format_qwen(ex: dict) -> dict:
    """Qwen2.5 ChatML 포맷 — CVSS 필드 포함"""
    text = (
        f"<|im_start|>system\n{SYSTEM}<|im_end|>\n"
        f"<|im_start|>user\n{ex['prompt']}<|im_end|>\n"
        f"<|im_start|>assistant\n{ex['completion']}<|im_end|>"
    )
    return {"text": text}


def tokenize(ex: dict, tokenizer) -> dict:
    out = tokenizer(ex["text"], truncation=True, max_length=MAX_LEN, padding=False)
    out["labels"] = out["input_ids"].copy()
    return out


def main() -> None:
    print("=" * 65)
    print("  ScanOps QLoRA v4 — Scratch 전체 재훈련")
    print(f"  데이터: {TRAIN_DATA.name}")
    print(f"  저장:   {OUT_DIR}")
    print(f"  디바이스: {DEVICE}  |  에포크: {EPOCHS}  |  LR: {LR}")
    print("=" * 65)

    # 데이터 크기 확인
    if not TRAIN_DATA.exists():
        print(f"오류: 학습 데이터 없음 — {TRAIN_DATA}")
        print("먼저 실행: python scripts/generate_train_v4_full.py")
        return

    # 토크나이저
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # 베이스 모델 로드 (어댑터 없이)
    print("\n[1/4] 베이스 모델 로드 중...")
    base = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        torch_dtype=torch.float16,
        device_map=None,
        trust_remote_code=True,
    ).to(DEVICE)

    # LoRA 어댑터 생성 (scratch)
    print("[2/4] LoRA 어댑터 생성 (scratch)...")
    lora_cfg = LoraConfig(
        r=LORA_R,
        lora_alpha=LORA_ALPHA,
        lora_dropout=LORA_DROPOUT,
        bias="none",
        task_type=TaskType.CAUSAL_LM,
        target_modules=LORA_TARGETS,
    )
    model = get_peft_model(base, lora_cfg)
    model.print_trainable_parameters()

    # 데이터 준비
    print("\n[3/4] 데이터 전처리 중...")
    ds = load_data()
    ds = ds.map(format_qwen)
    ds = ds.map(lambda x: tokenize(x, tokenizer), remove_columns=ds.column_names)
    print(f"      토크나이즈 완료: {len(ds):,}개 (max_len={MAX_LEN})")

    # 샘플 통계
    lengths = [len(ds[i]["input_ids"]) for i in range(min(100, len(ds)))]
    print(f"      길이 통계 (첫 100개): min={min(lengths)} avg={sum(lengths)//len(lengths)} max={max(lengths)}")

    # 훈련 설정
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    total_steps = (len(ds) // (BATCH * GRAD_ACCUM)) * EPOCHS

    args = TrainingArguments(
        output_dir=str(OUT_DIR),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH,
        gradient_accumulation_steps=GRAD_ACCUM,
        learning_rate=LR,
        warmup_steps=WARMUP_STEPS,
        lr_scheduler_type="cosine",
        fp16=False,
        bf16=False,
        logging_steps=20,
        save_strategy="epoch",
        save_total_limit=2,
        report_to="none",
        dataloader_pin_memory=False,
        optim="adamw_torch",
        weight_decay=0.01,
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=ds,
        data_collator=DataCollatorForSeq2Seq(
            tokenizer, pad_to_multiple_of=8, return_tensors="pt"
        ),
    )

    # 학습 시작
    print(f"\n[4/4] 학습 시작  (총 스텝: ~{total_steps})")
    print("      ─" * 30)
    t0 = time.time()
    result = trainer.train()
    elapsed = time.time() - t0

    # 최종 어댑터 저장
    final_dir = OUT_DIR / "final"
    final_dir.mkdir(exist_ok=True)
    model.save_pretrained(str(final_dir))
    tokenizer.save_pretrained(str(final_dir))

    # 학습 로그 저장
    log_path = OUT_DIR / "train_log_v4.json"
    log_data = {
        "epochs": EPOCHS,
        "samples": len(ds),
        "lora_r": LORA_R,
        "lora_alpha": LORA_ALPHA,
        "learning_rate": LR,
        "elapsed_min": round(elapsed / 60, 1),
        "final_loss": round(result.training_loss, 4),
        "log_history": trainer.state.log_history,
    }
    log_path.write_text(json.dumps(log_data, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n" + "=" * 65)
    print(f"  ✓ 완료!  {elapsed / 60:.1f}분  |  최종 손실: {result.training_loss:.4f}")
    print(f"  저장 경로: {final_dir}")
    print(f"  학습 로그: {log_path}")
    print("=" * 65)
    print("\n다음 단계:")
    print("  python scripts/convert_to_gguf_v4.py")


if __name__ == "__main__":
    main()
