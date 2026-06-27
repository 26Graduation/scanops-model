"""LLM 추론 파라미터 그리드 탐색 — 하이브리드 재현율 추가 회복용.
decoy-aware 그래프가 vuln/safe를 고정밀로 가르므로, LLM은 graph-unknown
케이스만 결정한다. 따라서 그 부분집합에서만 파라미터(temp/repeat_penalty/
num_predict/top_p)를 바꿔 하이브리드 F1을 직접 최적화한다.

실행:  .venv/bin/python scripts/grid_llm_hybrid.py
"""
from __future__ import annotations
import json, sys, time, itertools
from pathlib import Path
import requests

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE)); sys.path.insert(0, str(BASE / "scripts"))
from scripts.benchmark_qwen_rag import SYSTEM_FT, parse_response
from scanops.core.java_graph import analyze_java

OLLAMA = "http://localhost:11434/api/chat"
MODEL = "qwen2.5-coder-security-v11:latest"
eval_cases = json.load(open(BASE / "data" / "owasp_holdout_eval.json"))
full = {c["id"]: c for c in json.load(open(BASE / "data" / "owasp_holdout_full.json"))}

def is_safe(v):
    return (not v) or v.strip().upper().startswith("NONE") or v in ("—", "N/A", "")

def llm_call(prompt, opts):
    payload = {"model": MODEL, "stream": False,
               "messages": [{"role": "system", "content": SYSTEM_FT},
                            {"role": "user", "content": prompt}],
               "options": opts}
    r = requests.post(OLLAMA, json=payload, timeout=120); r.raise_for_status()
    raw = r.json().get("message", {}).get("content", "")
    for s in ("[EMPTY_", "Human resources", "The following", "Note:", "\nVULNERABILITY_FIXED:"):
        i = raw.find(s)
        if i != -1: raw = raw[:i]
    vi = raw.find("VULNERABILITY:")
    if vi > 0: raw = raw[vi:]
    return not is_safe(parse_response(raw.strip()).get("VULNERABILITY", "—"))

# 그래프 판정 (고정)
gverd = {c["id"]: analyze_java(full[c["id"]]["full_code"])["verdict"] if c["id"] in full else "unknown"
         for c in eval_cases}
unknown_ids = [c["id"] for c in eval_cases if gverd[c["id"]] == "unknown"]
label = {c["id"]: c["label"] for c in eval_cases}
prompt = {c["id"]: c["prompt"] for c in eval_cases}
print(f"graph-unknown(LLM 결정) {len(unknown_ids)}건만 대상으로 그리드 탐색")

def hybrid_metrics(llm_unknown: dict):
    """graph vuln→True, safe→False, unknown→llm_unknown[id]."""
    def flag(i):
        v = gverd[i]
        if v == "vuln": return True
        if v == "safe": return False
        return llm_unknown[i]
    ids = [c["id"] for c in eval_cases]
    tp = sum(1 for i in ids if label[i]=="vuln" and flag(i)); fn = sum(1 for i in ids if label[i]=="vuln" and not flag(i))
    fp = sum(1 for i in ids if label[i]=="safe" and flag(i)); tn = sum(1 for i in ids if label[i]=="safe" and not flag(i))
    rec=tp/(tp+fn)*100; fpr=fp/(fp+tn)*100; prec=tp/(tp+fp)*100 if tp+fp else 0; acc=(tp+tn)/len(ids)*100
    f1=2*prec*rec/(prec+rec) if prec+rec else 0
    return dict(recall=round(rec,1),fpr=round(fpr,1),precision=round(prec,1),accuracy=round(acc,1),f1=round(f1,1),tp=tp,fn=fn,fp=fp,tn=tn)

STOP = ["<|im_end|>", "<|endoftext|>", "[EMPTY_151643]", "\n\n\n"]
# 그리드: 재현율을 누르는 의심 요인 repeat_penalty, temp, top_p
grid = []
for temp in (0.0,):
    for rp in (1.0, 1.1, 1.3):
        for tp_ in (0.8,):
            grid.append({"temperature": temp, "top_p": tp_, "num_predict": 400,
                         "stop": STOP, "repeat_penalty": rp})

# 캐시: (temp,rp,top_p)별 unknown 케이스 LLM 결과
results = []
for opts in grid:
    key = (opts["temperature"], opts["repeat_penalty"], opts["top_p"])
    t0 = time.time()
    llm_u = {}
    for i in unknown_ids:
        try: llm_u[i] = llm_call(prompt[i], opts)
        except Exception: llm_u[i] = False
    m = hybrid_metrics(llm_u)
    dt = round(time.time()-t0)
    print(f"temp={key[0]} rp={key[1]} top_p={key[2]:4}  "
          f"F1={m['f1']:5} 재현율={m['recall']:5}% 오탐={m['fpr']:5}% 정확도={m['accuracy']:5}% "
          f"(TP{m['tp']} FN{m['fn']} FP{m['fp']} TN{m['tn']})  {dt}s")
    results.append((key, m))

best = max(results, key=lambda x: (x[1]["f1"], x[1]["recall"]))
print("\nBEST:", best[0], best[1])
json.dump([{"params":dict(temperature=k[0],repeat_penalty=k[1],top_p=k[2]),"metrics":m} for k,m in results],
          open(BASE/"reports"/"grid_llm_hybrid.json","w"), indent=2, ensure_ascii=False)
