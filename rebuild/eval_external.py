"""
ScanOps 재구축 — 외부 벤치마크 채점: 우리 모델 (RunPod GPU에서 실행)
=====================================================================
build_external_bench.py가 만든 {primevul,cleanvul}_test.jsonl을
학습된 어댑터로 추론하고 채점한다. 추론 방식은 eval_test.py와 완전히 동일
(같은 모델 로드, 같은 chat template, greedy 생성). 다른 건 데이터와 채점 범위뿐.

채점 (bench_common.py):
  ① 이진(취약/안전): 재현율 / 오탐률 / 정밀도 / F1  ← 내부 test 표와 나란히 붙는 지표
  ② 쌍 단위(PrimeVul 공식 프로토콜): P-C / P-V / P-B / P-R
     CleanVul도 쌍 구조라 같은 지표를 함께 산출(보조 지표).
  ※ CWE/SEVERITY 일치율은 외부에서 채점하지 않음 — CleanVul은 CWE 라벨 부재,
    PrimeVul은 라벨 체계 비정합. (모델 출력 4줄 포맷 자체는 그대로 유지)

출력: out/external_{name}_predictions.jsonl, out/external_{name}_report.json

실행 (pod, 학습 때와 같은 환경):
  python rebuild/eval_external.py primevul
  python rebuild/eval_external.py cleanvul
"""
from __future__ import annotations

from unsloth import FastLanguageModel

import json
import sys
from pathlib import Path

import torch

from bench_common import build_report, load_jsonl, parse

ROOT = Path(__file__).resolve().parent
ADAPTER = ROOT / "out" / "adapter"
BATCH = 4      # 한 번에 GPU에 넣는 문제 수 (24GB 기준)
MAX_NEW = 180  # 4줄 답안 상한 토큰

name = sys.argv[1] if len(sys.argv) > 1 else "primevul"
DATASET = ROOT / "data" / f"{name}_test.jsonl"
OUT_PRED = ROOT / "out" / f"external_{name}_predictions.jsonl"
OUT_REPORT = ROOT / "out" / f"external_{name}_report.json"

# ── 모델 로드 (eval_test.py와 동일: 베이스 4bit + LoRA 어댑터, 추론 모드) ─────
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=str(ADAPTER),
    max_seq_length=4096 + MAX_NEW,
    load_in_4bit=True,
)
FastLanguageModel.for_inference(model)

# Qwen3.5-9B는 멀티모달 프로세서라 내부 텍스트 토크나이저로 우회 (eval_test.py와 동일)
text_tok = getattr(tokenizer, "tokenizer", tokenizer)
text_tok.padding_side = "left"
_PAD = text_tok.pad_token_id or text_tok.eos_token_id

rows = load_jsonl(DATASET)
print(f"[{name}] {len(rows)}건 채점 시작")


def generate_batch(prompts: list[str]) -> list[str]:
    texts = [
        tokenizer.apply_chat_template(
            [{"role": "user", "content": p}],
            tokenize=False,
            add_generation_prompt=True,
            enable_thinking=False,     # <think> 블록 억제, 4줄 직행
        )
        for p in prompts
    ]
    enc = text_tok(texts, return_tensors="pt", padding=True,
                   truncation=True, max_length=4096).to(model.device)
    with torch.no_grad():
        out = model.generate(**enc, max_new_tokens=MAX_NEW,
                             do_sample=False,          # greedy — 재현 가능
                             pad_token_id=_PAD)
    gen = out[:, enc["input_ids"].shape[1]:]
    return text_tok.batch_decode(gen, skip_special_tokens=True)


preds = []
for i in range(0, len(rows), BATCH):
    batch = rows[i:i + BATCH]
    outs = generate_batch([r["prompt"] for r in batch])
    for r, o in zip(batch, outs):
        preds.append({"meta": r["meta"], "raw": o.strip(), **parse(o)})
    if (i // BATCH) % 25 == 0:
        print(f"{i + len(batch)}/{len(rows)}", flush=True)

OUT_PRED.parent.mkdir(exist_ok=True)
with OUT_PRED.open("w") as f:
    for p in preds:
        f.write(json.dumps(p, ensure_ascii=False) + "\n")

report = build_report(preds, engine="scanops-qwen3.5-9b-qlora", dataset=name)
OUT_REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2))
print(json.dumps({k: report[k] for k in ("overall", "pairwise") if k in report}, indent=2))
print(f"저장: {OUT_PRED}, {OUT_REPORT}")
