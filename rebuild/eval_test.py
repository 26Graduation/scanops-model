"""
ScanOps 재구축 — test 채점 (학습에 쓰인 pod에서 실행)
======================================================
학습된 어댑터로 test.jsonl 1,197건을 추론하고 4줄 출력을 파싱해 채점한다.

채점 (보고서 §6.1):
  ① 취약 여부: 재현율(recall) / 오탐률(FPR) / F1
  ② CWE 일치율 (취약 정답 건 중)
  ③ SEVERITY 등급 일치율 (취약 정답 건 중)
  + 언어별 / CWE별 분해

출력: out/test_predictions.jsonl (건별 예측), out/test_report.json (요약)
"""
from __future__ import annotations

from unsloth import FastLanguageModel

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import torch

ROOT = Path(__file__).resolve().parent
ADAPTER = ROOT / "out" / "adapter"
TEST = ROOT / "data" / "test.jsonl"
OUT_PRED = ROOT / "out" / "test_predictions.jsonl"
OUT_REPORT = ROOT / "out" / "test_report.json"
BATCH = 4
MAX_NEW = 180

# ── 모델 로드 (베이스 4bit + LoRA 어댑터) ─────────────────────────────────────
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=str(ADAPTER),
    max_seq_length=4096 + MAX_NEW,
    load_in_4bit=True,
)
FastLanguageModel.for_inference(model)

# Qwen3.5-9B는 Qwen3VLProcessor(멀티모달) — 텍스트만 넣으면 이미지 처리기가 크래시.
# 내부 텍스트 토크나이저를 직접 써서 우회한다.
text_tok = getattr(tokenizer, "tokenizer", tokenizer)
text_tok.padding_side = "left"  # 배치 생성 시 왼쪽 패딩 필수
_PAD = text_tok.pad_token_id or text_tok.eos_token_id

rows = [json.loads(l) for l in TEST.open()]
print(f"test {len(rows)}건 채점 시작")

# ── 추론 ─────────────────────────────────────────────────────────────────────
def generate_batch(prompts: list[str]) -> list[str]:
    texts = [
        tokenizer.apply_chat_template(
            [{"role": "user", "content": p}],
            tokenize=False, add_generation_prompt=True,
            enable_thinking=False,   # 하이브리드 추론 모델 — <think> 블록 억제, 4줄 직행
        )
        for p in prompts
    ]
    enc = text_tok(texts, return_tensors="pt", padding=True, truncation=True,
                   max_length=4096).to(model.device)
    with torch.no_grad():
        out = model.generate(
            **enc, max_new_tokens=MAX_NEW, do_sample=False, pad_token_id=_PAD,
        )
    gen = out[:, enc["input_ids"].shape[1]:]
    return text_tok.batch_decode(gen, skip_special_tokens=True)

# ── 파싱: 4줄 출력 → (label, cwe, severity) ──────────────────────────────────
def parse(text: str) -> dict:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)  # 남은 추론 블록 제거
    vuln_line = ""
    sev_line = ""
    for line in text.splitlines():
        s = line.strip()
        if s.upper().startswith("VULNERABILITY:") and not vuln_line:
            vuln_line = s.split(":", 1)[1].strip()
        elif s.upper().startswith("SEVERITY:") and not sev_line:
            sev_line = s.split(":", 1)[1].strip().upper()
    if not vuln_line:
        return {"label": "parse_fail", "cwe": "", "severity": ""}
    if vuln_line.upper().startswith("NONE"):
        return {"label": "safe", "cwe": "", "severity": "NONE"}
    m = re.search(r"CWE-\d+", vuln_line)
    return {"label": "vuln", "cwe": m.group(0) if m else "", "severity": sev_line}

# ── 실행 ─────────────────────────────────────────────────────────────────────
preds = []
for i in range(0, len(rows), BATCH):
    batch = rows[i:i + BATCH]
    outs = generate_batch([r["prompt"] for r in batch])
    for r, o in zip(batch, outs):
        preds.append({"meta": r["meta"], "raw": o.strip(), **parse(o)})
    if (i // BATCH) % 25 == 0:
        print(f"{i + len(batch)}/{len(rows)}")

with OUT_PRED.open("w") as f:
    for p in preds:
        f.write(json.dumps(p, ensure_ascii=False) + "\n")

# ── 채점 ─────────────────────────────────────────────────────────────────────
def score(items: list[dict]) -> dict:
    vuln_gold = [p for p in items if p["meta"]["label"] == "vuln"]
    safe_gold = [p for p in items if p["meta"]["label"] == "safe"]
    tp = sum(1 for p in vuln_gold if p["label"] == "vuln")
    fp = sum(1 for p in safe_gold if p["label"] == "vuln")
    recall = tp / len(vuln_gold) if vuln_gold else 0.0
    fpr = fp / len(safe_gold) if safe_gold else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    cwe_ok = sum(1 for p in vuln_gold if p["label"] == "vuln" and p["cwe"] == p["meta"]["cwe_id"])
    sev_ok = sum(1 for p in vuln_gold if p["label"] == "vuln" and p["severity"] == p["meta"]["severity"])
    return {
        "n": len(items), "n_vuln": len(vuln_gold), "n_safe": len(safe_gold),
        "recall": round(recall, 4), "fpr": round(fpr, 4),
        "precision": round(precision, 4), "f1": round(f1, 4),
        "cwe_acc_on_vuln": round(cwe_ok / len(vuln_gold), 4) if vuln_gold else 0.0,
        "sev_acc_on_vuln": round(sev_ok / len(vuln_gold), 4) if vuln_gold else 0.0,
        "parse_fail": sum(1 for p in items if p["label"] == "parse_fail"),
    }

report = {"overall": score(preds), "by_language": {}, "by_cwe": {}}
by_lang = defaultdict(list)
for p in preds:
    by_lang[p["meta"]["lang_group"]].append(p)
for lang, items in sorted(by_lang.items()):
    report["by_language"][lang] = score(items)

top_cwes = [c for c, _ in Counter(
    p["meta"]["cwe_id"] for p in preds if p["meta"]["label"] == "vuln").most_common(10)]
for cwe in top_cwes:
    items = [p for p in preds if p["meta"]["cwe_id"] == cwe and p["meta"]["label"] == "vuln"]
    report["by_cwe"][cwe] = {
        "n": len(items),
        "recall": round(sum(1 for p in items if p["label"] == "vuln") / len(items), 4),
        "cwe_acc": round(sum(1 for p in items if p["cwe"] == cwe) / len(items), 4),
    }

OUT_REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2))
print(json.dumps(report["overall"], indent=2))
print("언어별:", json.dumps(report["by_language"], indent=2))
print(f"저장: {OUT_PRED}, {OUT_REPORT}")
