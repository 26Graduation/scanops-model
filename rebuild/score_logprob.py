"""
ScanOps v3 — (D) logprob 연속점수 추출 (사양서 §6-D)
====================================================
생성 없이 forward 1회로 "취약 vs 안전"의 연속 점수를 뽑는다.

원리:
  모델의 답안 첫 줄은 항상 "VULNERABILITY: <CWE-id ...> 또는 NONE".
  assistant 응답 접두사로 "VULNERABILITY:"까지 강제로 넣고 forward 1회를 돌리면,
  바로 다음 토큰의 분포가 곧 모델의 이진 판단이다.
    score = logP(" CWE" 계열 첫 토큰) - logP(" NONE" 첫 토큰)
  이 score의 임계값을 스윕하면 ROC 곡선 전체를 얻는다. (생성 k회가 필요 없어 (A)보다 훨씬 쌈)

주의:
  - greedy 생성과의 정합성 확인용으로 argmax(두 후보) 라벨도 같이 저장한다.
  - 채점·파서는 bench_common을 그대로 쓴다(포맷 변경 금지 — 공정 비교 유지).

출력: out/{tag}_logprob_{name}.jsonl  (meta, score, p_vuln, argmax_label)
실행: python rebuild/score_logprob.py <adapter_dir> <tag> <name1> [name2 ...]
      예) python rebuild/score_logprob.py out/adapter v1 primevul_tune primevul_report
"""
from __future__ import annotations

from unsloth import FastLanguageModel

import json
import sys
import time
from pathlib import Path

import torch
import torch.nn.functional as F

ROOT = Path(__file__).resolve().parent
MAX_LEN = 4096
BATCH = 8

adapter = sys.argv[1]
tag = sys.argv[2]
names = sys.argv[3:]

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=str(ROOT / adapter) if not adapter.startswith("/") else adapter,
    max_seq_length=MAX_LEN + 8,
    load_in_4bit=True,
)
FastLanguageModel.for_inference(model)

text_tok = getattr(tokenizer, "tokenizer", tokenizer)
text_tok.padding_side = "left"
_PAD = text_tok.pad_token_id or text_tok.eos_token_id

# ── 후보 첫 토큰 확정 ────────────────────────────────────────────────────────
# "VULNERABILITY:" 다음에 올 수 있는 것: " NONE" / " CWE-123 (...)"
NONE_IDS = text_tok(" NONE", add_special_tokens=False)["input_ids"]
CWE_IDS = text_tok(" CWE", add_special_tokens=False)["input_ids"]
print(f"[tok] ' NONE' -> {NONE_IDS} / ' CWE' -> {CWE_IDS}", flush=True)
assert NONE_IDS[0] != CWE_IDS[0], "첫 토큰이 같으면 1위치 비교가 불가 — 접두사 길이를 늘려야 함"
NONE_T, CWE_T = NONE_IDS[0], CWE_IDS[0]

PREFIX = "VULNERABILITY:"


def build_text(prompt: str) -> str:
    base = tokenizer.apply_chat_template(
        [{"role": "user", "content": prompt}],
        tokenize=False, add_generation_prompt=True, enable_thinking=False,
    )
    return base + PREFIX


for name in names:
    rows = [json.loads(l) for l in (ROOT / "data" / f"{name}.jsonl").open()]
    out_path = ROOT / "out" / f"{tag}_logprob_{name}.jsonl"
    recs = []
    t0 = time.time()
    for i in range(0, len(rows), BATCH):
        batch = rows[i:i + BATCH]
        enc = text_tok([build_text(r["prompt"]) for r in batch], return_tensors="pt",
                       padding=True, truncation=True, max_length=MAX_LEN).to(model.device)
        with torch.no_grad():
            logits = model(**enc).logits[:, -1, :].float()
        logp = F.log_softmax(logits, dim=-1)
        for r, lp in zip(batch, logp):
            a, b = lp[CWE_T].item(), lp[NONE_T].item()
            recs.append({
                "meta": r["meta"],
                "score": round(a - b, 6),              # >0 이면 취약 쪽
                "logp_vuln": round(a, 6), "logp_none": round(b, 6),
                "argmax_label": "vuln" if a > b else "safe",
            })
        if (i // BATCH) % 25 == 0:
            el = time.time() - t0
            print(f"{name} {i + len(batch)}/{len(rows)} ({el:.0f}s)", flush=True)
    with out_path.open("w") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    dt = time.time() - t0
    print(f"[{name}] {len(recs)}건 {dt:.0f}s ({dt/max(1,len(recs))*1000:.0f}ms/건) -> {out_path}", flush=True)
print("LOGPROB_DONE")
