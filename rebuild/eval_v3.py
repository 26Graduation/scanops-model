"""
ScanOps v3 — 통합 추론·채점 (greedy / self-consistency 공용)
============================================================
어댑터 하나를 받아 지정한 split들을 추론하고 bench_common으로 채점한다.
파서·지표는 bench_common 그대로(공정 비교 유지). 바꾼 것은 "어떤 어댑터/어떤 운영점"뿐.

모드:
  greedy  — do_sample=False, MAX_NEW=180 (4줄 전체 → 내부 test의 CWE/SEV 채점까지 가능)
  sample  — temperature 0.7, k회 샘플, MAX_NEW=24 (이진 판정만 필요 → 비용 1/7)
            각 건의 vuln 표 수를 저장 → 임계 t를 사후 스윕 (사양서 §6-A)

비용도 함께 기록한다(건당 초, 샘플 수) — 사양서 §6 "성능-비용 파레토" 요구사항.

실행:
  python rebuild/eval_v3.py <adapter> <tag> <mode> <k> <split> [split...]
  예) python rebuild/eval_v3.py out/v3_r16_s42 v3 greedy 1 test primevul_report
      python rebuild/eval_v3.py out/v3_r16_s42 v3 sample 5 primevul_tune
"""
from __future__ import annotations

from unsloth import FastLanguageModel

import json
import sys
import time
from pathlib import Path

import torch

from bench_common import build_report, load_jsonl, parse

ROOT = Path(__file__).resolve().parent
adapter, tag, mode, k = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
splits = sys.argv[5:]

MAX_NEW = 180 if mode == "greedy" else 24
BATCH = 8 if mode == "greedy" else 16
MAX_LEN = 4096

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=adapter if adapter.startswith("/") else str(ROOT / adapter),
    max_seq_length=MAX_LEN + MAX_NEW, load_in_4bit=True,
)
FastLanguageModel.for_inference(model)
text_tok = getattr(tokenizer, "tokenizer", tokenizer)
text_tok.padding_side = "left"
_PAD = text_tok.pad_token_id or text_tok.eos_token_id


def gen(prompts: list[str], sample: bool) -> list[str]:
    texts = [tokenizer.apply_chat_template([{"role": "user", "content": p}], tokenize=False,
                                           add_generation_prompt=True, enable_thinking=False)
             for p in prompts]
    enc = text_tok(texts, return_tensors="pt", padding=True,
                   truncation=True, max_length=MAX_LEN).to(model.device)
    with torch.no_grad():
        out = model.generate(**enc, max_new_tokens=MAX_NEW, pad_token_id=_PAD,
                             **({"do_sample": True, "temperature": 0.7, "top_p": 0.95}
                                if sample else {"do_sample": False}))
    return text_tok.batch_decode(out[:, enc["input_ids"].shape[1]:], skip_special_tokens=True)


for name in splits:
    rows = load_jsonl(ROOT / "data" / f"{name}.jsonl")
    t0 = time.time()
    if mode == "greedy":
        preds = []
        for i in range(0, len(rows), BATCH):
            b = rows[i:i + BATCH]
            for r, o in zip(b, gen([x["prompt"] for x in b], sample=False)):
                preds.append({"meta": r["meta"], "raw": o.strip(), **parse(o)})
            if (i // BATCH) % 20 == 0:
                print(f"{name} {i+len(b)}/{len(rows)} ({time.time()-t0:.0f}s)", flush=True)
        out_pred = ROOT / "out" / f"{tag}_{name}_predictions.jsonl"
        report = build_report(preds, engine=f"scanops-{tag}", dataset=name)
    else:
        votes = [[] for _ in rows]
        for run in range(k):
            for i in range(0, len(rows), BATCH):
                b = rows[i:i + BATCH]
                for j, o in enumerate(gen([x["prompt"] for x in b], sample=True)):
                    votes[i + j].append(parse(o)["label"])
            print(f"{name} sample {run+1}/{k} ({time.time()-t0:.0f}s)", flush=True)
        preds = []
        for r, v in zip(rows, votes):
            nv = sum(1 for x in v if x == "vuln")
            preds.append({"meta": r["meta"], "votes": v, "n_vuln_votes": nv, "k": k,
                          "label": "vuln" if nv * 2 > k else "safe"})   # 기본 다수결(참고용)
        out_pred = ROOT / "out" / f"{tag}_{name}_votes_k{k}.jsonl"
        report = build_report(preds, engine=f"scanops-{tag}-sc{k}", dataset=name)

    dt = time.time() - t0
    report["cost"] = {"mode": mode, "k": k, "n": len(rows), "total_secs": round(dt, 1),
                      "secs_per_case": round(dt / max(1, len(rows)), 3),
                      "samples_per_case": k, "max_new_tokens": MAX_NEW}
    with out_pred.open("w") as f:
        for p in preds:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")
    rp = ROOT / "out" / f"{out_pred.stem.replace('_predictions','').replace('_votes','_votes')}_report.json"
    rp.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps({"overall": report["overall"], "cost": report["cost"],
                      "pairwise": report.get("pairwise", {}).get("pair_correct")},
                     ensure_ascii=False), flush=True)
print("EVAL_V3_DONE")
