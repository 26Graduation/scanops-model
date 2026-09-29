"""
CTX-1 — arm별 logprob 연속 점수 (사양서 §4-3)
=============================================
`score_logprob.py`와 **완전히 같은 점수 정의**를 쓴다:
    assistant 접두사 "VULNERABILITY:" 강제 → forward 1회 → score = logP(' CWE') - logP(' NONE')

원본과 달라지는 곳은 딱 두 군데이고, 둘 다 문맥 주입 때문에 불가피하다:

  1) MAX_LEN 4096 → 12288.
     T1 프롬프트는 최대 7.3k 토큰이라 4096으로는 잘린다.
  2) truncation_side = "left".
     원본은 기본값(right)이라, 4096을 넘는 입력에서는 **문장 끝의
     "VULNERABILITY:" 접두사가 잘려나가** 점수 정의 자체가 무너진다.
     왼쪽(문맥 앞부분)을 버려야 접두사가 살아남는다.

  ※ 어댑터·프롬프트 꼬리·점수 정의·토큰 후보는 손대지 않았다.

실행: python rebuild/ctx_score_logprob.py <adapter_dir> <tag> <arm1> [arm2 ...]
      예) python ctx_score_logprob.py out/adapter ctx T0 T1 T1shuf T1nofunc
      CTX_SUFFIX=_tune 를 주면 data/ctx_{arm}_tune.jsonl 을 읽어 tune split을 채점한다
      (사양서 §4-7: 임계값 τ는 tune split에서만 고른다).
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
MAX_LEN = 12288
import os
BATCH = int(os.environ.get("CTX_BATCH", "2"))
SUFFIX = os.environ.get("CTX_SUFFIX", "")          # "" = report split, "_tune" = tune split
SPLIT = "primevul_tune" if SUFFIX == "_tune" else "primevul_report"

adapter = sys.argv[1]
tag = sys.argv[2]
arms = sys.argv[3:]

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=str(ROOT / adapter) if not adapter.startswith("/") else adapter,
    max_seq_length=MAX_LEN + 8,
    load_in_4bit=True,
)
FastLanguageModel.for_inference(model)

text_tok = getattr(tokenizer, "tokenizer", tokenizer)
text_tok.padding_side = "left"
text_tok.truncation_side = "left"          # ← 접두사 보존 (§위 2번)
_PAD = text_tok.pad_token_id or text_tok.eos_token_id

NONE_IDS = text_tok(" NONE", add_special_tokens=False)["input_ids"]
CWE_IDS = text_tok(" CWE", add_special_tokens=False)["input_ids"]
print(f"[tok] ' NONE' -> {NONE_IDS} / ' CWE' -> {CWE_IDS}", flush=True)
assert NONE_IDS[0] != CWE_IDS[0], "첫 토큰이 같으면 1위치 비교 불가"
NONE_T, CWE_T = NONE_IDS[0], CWE_IDS[0]

PREFIX = "VULNERABILITY:"


def build_text(prompt: str) -> str:
    base = tokenizer.apply_chat_template(
        [{"role": "user", "content": prompt}],
        tokenize=False, add_generation_prompt=True, enable_thinking=False,
    )
    return base + PREFIX


for arm in arms:
    rows = [json.loads(l) for l in (ROOT / "data" / f"ctx_{arm}{SUFFIX}.jsonl").open()]
    out_path = ROOT / "out" / f"{tag}_{arm}_logprob_{SPLIT}.jsonl"
    recs = []
    t0 = time.time()
    n_trunc = 0
    for i in range(0, len(rows), BATCH):
        batch = rows[i:i + BATCH]
        texts = [build_text(r["prompt"]) for r in batch]
        enc = text_tok(texts, return_tensors="pt", padding=True,
                       truncation=True, max_length=MAX_LEN).to(model.device)
        n_trunc += sum(1 for t in texts
                       if len(text_tok(t, add_special_tokens=False)["input_ids"]) > MAX_LEN)
        with torch.no_grad():
            try:
                logits = model(**enc, logits_to_keep=1).logits[:, -1, :].float()
            except TypeError:
                logits = model(**enc).logits[:, -1, :].float()
        logp = F.log_softmax(logits, dim=-1)
        for r, lp in zip(batch, logp):
            a, b = lp[CWE_T].item(), lp[NONE_T].item()
            recs.append({
                "meta": r["meta"],
                "score": round(a - b, 6),
                "logp_vuln": round(a, 6), "logp_none": round(b, 6),
                "argmax_label": "vuln" if a > b else "safe",
            })
        if (i // BATCH) % 25 == 0:
            print(f"{arm} {i + len(batch)}/{len(rows)} ({time.time()-t0:.0f}s)", flush=True)
    with out_path.open("w") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    dt = time.time() - t0
    print(f"[{arm}] {len(recs)}건 {dt:.0f}s ({dt/max(1,len(recs))*1000:.0f}ms/건) "
          f"truncated={n_trunc} -> {out_path}", flush=True)
print("CTX_LOGPROB_DONE")
