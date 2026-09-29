"""
ScanOps 재구축 — v3 QLoRA 학습 (사양서 §5)
===========================================
v2 실패의 2차 원인을 고친다: 체크포인트 선택 기준.

  v2: metric_for_best_model="eval_loss"
      → val이 86% safe였던 탓에 "항상 SAFE"가 val loss 최적해가 됐다.
  v3: 매 eval마다 val 층화 표본을 실제로 **생성**해 bench_common으로 채점,
      **생성 기반 F1**을 최적 체크포인트 기준으로 쓴다.
      (eval_loss도 계속 로깅은 하되 선택 기준으로 쓰지 않는다)

환경변수:
  TRAIN_SPLIT / VAL_SPLIT   기본 train_v3 / val_v3
  LORA_RANK                 기본 16
  SEED                      기본 42
  OUT_NAME                  산출 어댑터 디렉터리명 (기본 v3_r16_s42) — v1 어댑터를 덮지 않는다
  EVAL_STEPS                기본 150
  GEN_EVAL_N                생성 채점 표본 수 (기본 200)
  MAX_STEPS                 (선택) 시간 예산에 맞춘 상한
  LEARNING_RATE             기본 2e-4 (v3 재현성 유지). V4-TRAIN 은 1e-4 를 넘긴다
"""
from __future__ import annotations

from unsloth import FastLanguageModel
from unsloth.chat_templates import train_on_responses_only

import json
import os
import random
import time
from pathlib import Path

import torch
from datasets import Dataset
from transformers import EarlyStoppingCallback, TrainerCallback
from trl import SFTConfig, SFTTrainer

from bench_common import parse, score

MODEL_ID = "unsloth/Qwen3.5-9B"
MAX_SEQ_LEN = 4096
LORA_RANK = int(os.environ.get("LORA_RANK", 16))
LORA_ALPHA = LORA_RANK * 2
LEARNING_RATE = float(os.environ.get("LEARNING_RATE", 2e-4))
MAX_EPOCHS = float(os.environ.get("MAX_EPOCHS", 2))
EARLY_STOP_PATIENCE = 3
BATCH_PER_DEVICE = int(os.environ.get("BATCH_PER_DEVICE", 8))   # A100 80GB
GRAD_ACCUM = int(os.environ.get("GRAD_ACCUM", 2))               # 유효 배치 16
SEED = int(os.environ.get("SEED", 42))
EVAL_STEPS = int(os.environ.get("EVAL_STEPS", 150))
GEN_EVAL_N = int(os.environ.get("GEN_EVAL_N", 200))
OUT_NAME = os.environ.get("OUT_NAME", f"v3_r{LORA_RANK}_s{SEED}")

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
OUT_DIR = ROOT / "out"

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=MODEL_ID, max_seq_length=MAX_SEQ_LEN, load_in_4bit=True, dtype=None,
)
model = FastLanguageModel.get_peft_model(
    model, r=LORA_RANK, lora_alpha=LORA_ALPHA, lora_dropout=0.0,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                    "gate_proj", "up_proj", "down_proj"],
    use_gradient_checkpointing="unsloth", random_state=SEED,
)

text_tok = getattr(tokenizer, "tokenizer", tokenizer)


def load_rows(name: str) -> list[dict]:
    return [json.loads(l) for l in (DATA_DIR / f"{name}.jsonl").open()]


def to_dataset(rows: list[dict]) -> Dataset:
    def to_text(row):
        messages = [{"role": "user", "content": row["prompt"]},
                    {"role": "assistant", "content": row["completion"]}]
        return {"text": tokenizer.apply_chat_template(messages, tokenize=False)}
    return Dataset.from_list(rows).map(to_text, remove_columns=["prompt", "completion", "meta"])


train_rows = load_rows(os.environ.get("TRAIN_SPLIT", "train_v3"))
val_rows = load_rows(os.environ.get("VAL_SPLIT", "val_v3"))
train_ds = to_dataset(train_rows)
# eval_loss용 val은 400건으로 잘라 오버헤드를 줄인다(선택 기준은 어차피 생성 F1).
val_ds = to_dataset(val_rows[:400])
print(f"train {len(train_ds)} / val {len(val_ds)}", flush=True)


# ── 생성 기반 F1 콜백 (v2 실패의 2차 원인 처방) ──────────────────────────────
def stratified_sample(rows: list[dict], n: int) -> list[dict]:
    """라벨 균형을 맞춘 고정 표본 — 매 eval마다 같은 문제로 채점해야 비교가 된다."""
    rng = random.Random(0)
    vuln = [r for r in rows if r["meta"]["label"] == "vuln"]
    safe = [r for r in rows if r["meta"]["label"] == "safe"]
    rng.shuffle(vuln); rng.shuffle(safe)
    half = n // 2
    return vuln[:half] + safe[:n - half]


GEN_ROWS = stratified_sample(val_rows, GEN_EVAL_N)
GEN_BATCH = 16
GEN_MAX_NEW = 24        # 첫 줄(VULNERABILITY:)만 있으면 이진 채점 가능 → 짧게


class GenF1Callback(TrainerCallback):
    """eval 때마다 val 표본을 실제 생성해 F1을 계산하고 metrics에 주입한다.
    HF Trainer는 evaluate()가 돌려주는 metrics 딕셔너리로 best 체크포인트를 고르므로,
    on_evaluate에서 그 딕셔너리를 직접 채우면 metric_for_best_model로 쓸 수 있다."""

    def on_evaluate(self, args, state, control, metrics=None, **kw):
        if metrics is None:
            return
        t0 = time.time()
        FastLanguageModel.for_inference(model)
        tok = getattr(tokenizer, "tokenizer", tokenizer)
        old_side = tok.padding_side
        tok.padding_side = "left"
        pad = tok.pad_token_id or tok.eos_token_id
        preds = []
        try:
            for i in range(0, len(GEN_ROWS), GEN_BATCH):
                batch = GEN_ROWS[i:i + GEN_BATCH]
                texts = [tokenizer.apply_chat_template(
                    [{"role": "user", "content": r["prompt"]}], tokenize=False,
                    add_generation_prompt=True, enable_thinking=False) for r in batch]
                enc = tok(texts, return_tensors="pt", padding=True,
                          truncation=True, max_length=MAX_SEQ_LEN).to(model.device)
                with torch.no_grad():
                    out = model.generate(**enc, max_new_tokens=GEN_MAX_NEW,
                                         do_sample=False, pad_token_id=pad)
                gen = out[:, enc["input_ids"].shape[1]:]
                for r, o in zip(batch, tok.batch_decode(gen, skip_special_tokens=True)):
                    preds.append({"meta": r["meta"], **parse(o)})
        finally:
            tok.padding_side = old_side
            FastLanguageModel.for_training(model)
        s = score(preds)
        metrics["eval_gen_f1"] = s["f1"]
        metrics["eval_gen_recall"] = s["recall"]
        metrics["eval_gen_fpr"] = s["fpr"]
        metrics["eval_gen_parse_fail"] = s["parse_fail"]
        metrics["eval_gen_secs"] = round(time.time() - t0, 1)
        print(f"[GEN-F1 @step {state.global_step}] {json.dumps(s)} "
              f"({time.time()-t0:.0f}s)", flush=True)


cfg = dict(
    output_dir=str(OUT_DIR / f"checkpoints_{OUT_NAME}"),
    dataset_text_field="text",
    max_seq_length=MAX_SEQ_LEN,
    num_train_epochs=MAX_EPOCHS,
    learning_rate=LEARNING_RATE,
    lr_scheduler_type="cosine",
    warmup_ratio=0.03,
    per_device_train_batch_size=BATCH_PER_DEVICE,
    per_device_eval_batch_size=4,
    gradient_accumulation_steps=GRAD_ACCUM,
    bf16=True,
    logging_steps=20,
    eval_strategy="steps",
    eval_steps=EVAL_STEPS,
    save_strategy="steps",
    save_steps=EVAL_STEPS,
    save_total_limit=2,
    load_best_model_at_end=True,
    metric_for_best_model="eval_gen_f1",     # ★ v2와의 결정적 차이
    greater_is_better=True,
    seed=SEED,
    report_to="none",
)
if os.environ.get("MAX_STEPS"):
    cfg["max_steps"] = int(os.environ["MAX_STEPS"])

trainer = SFTTrainer(
    model=model, tokenizer=tokenizer,
    train_dataset=train_ds, eval_dataset=val_ds,
    args=SFTConfig(**cfg),
    callbacks=[GenF1Callback(), EarlyStoppingCallback(early_stopping_patience=EARLY_STOP_PATIENCE)],
)
trainer = train_on_responses_only(
    trainer, instruction_part="<|im_start|>user\n", response_part="<|im_start|>assistant\n")

stats = trainer.train()
print(stats)

adapter_dir = OUT_DIR / OUT_NAME
model.save_pretrained(str(adapter_dir))
tokenizer.save_pretrained(str(adapter_dir))
(OUT_DIR / f"{OUT_NAME}_trainlog.json").write_text(json.dumps(
    {"log_history": trainer.state.log_history,
     "best_metric": trainer.state.best_metric,
     "best_checkpoint": trainer.state.best_model_checkpoint,
     "config": {k: str(v) for k, v in cfg.items()}}, ensure_ascii=False, indent=2))
print(f"어댑터 저장 → {adapter_dir}")
print("TRAIN_V3_DONE")
