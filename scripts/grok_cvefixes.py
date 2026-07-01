"""Grok-3-mini를 CVEfixes 157케이스에 평가 → v12와 같은 지표로 비교."""
import sys, json
from pathlib import Path
BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE)); sys.path.insert(0, str(BASE / "scripts"))
from scripts.grok_client import query_llm
from scripts.benchmark_qwen_rag import build_ft_user_prompt, parse_response

def is_safe(v):
    return (not v) or v.strip() in ("—", "N/A", "") or v.strip().upper().startswith("NONE")

cases = [json.loads(l) for l in open(BASE / "data" / "cvefixes_benchmark.jsonl") if l.strip()]
rows = []
for i, c in enumerate(cases, 1):
    try:
        raw, _ = query_llm(build_ft_user_prompt(c["language"], c["code"]))
        flag = not is_safe(parse_response(raw).get("VULNERABILITY", "—"))
    except Exception as e:
        print(f"  {i} err {e}"); flag = False
    rows.append({"label": c["label"], "grok": flag})
    if i % 20 == 0: print(f"  {i}/{len(cases)}")

tp = sum(1 for r in rows if r["label"] == "vuln" and r["grok"])
fn = sum(1 for r in rows if r["label"] == "vuln" and not r["grok"])
fp = sum(1 for r in rows if r["label"] == "safe" and r["grok"])
tn = sum(1 for r in rows if r["label"] == "safe" and not r["grok"])
rec = tp/(tp+fn)*100 if tp+fn else 0
fpr = fp/(fp+tn)*100 if fp+tn else 0
prec = tp/(tp+fp)*100 if tp+fp else 0
acc = (tp+tn)/len(rows)*100
f1 = 2*prec*rec/(prec+rec) if prec+rec else 0
print("="*60)
print(f"Grok-3-mini @ CVEfixes 157:  F1={f1:.1f}  재현율={rec:.1f}%  오탐률={fpr:.1f}%  정확도={acc:.1f}%  (TP{tp} FN{fn} FP{fp} TN{tn})")
out = BASE / "reports" / "results_grok_cvefixes.json"
out.write_text(json.dumps({"f1":round(f1,1),"recall":round(rec,1),"fpr":round(fpr,1),"accuracy":round(acc,1),
                           "tp":tp,"fn":fn,"fp":fp,"tn":tn,"cases":rows}, indent=2, ensure_ascii=False))
print(f"저장: {out}")
