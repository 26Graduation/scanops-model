"""v12 LLM의 repeat_penalty 민감도 빠른 점검 — OWASP 균형 서브셋으로 FPR/재현율 비교."""
import sys, json, requests
sys.path.insert(0, ".")
sys.path.insert(0, "scripts")
from scripts.benchmark_qwen_rag import parse_response

M = "qwen2.5-coder-security-v12:latest"
SYS = "You are a security code analyzer."
cases = json.load(open("data/owasp_holdout_eval.json"))
vuln = [c for c in cases if c["label"] == "vuln"][:15]
safe = [c for c in cases if c["label"] == "safe"][:15]
subset = vuln + safe

def ask(prompt, rp):
    r = requests.post("http://localhost:11434/api/chat", json={
        "model": M, "messages": [{"role": "system", "content": SYS}, {"role": "user", "content": prompt}],
        "stream": False, "options": {"temperature": 0, "repeat_penalty": rp, "num_predict": 400,
                                      "stop": ["<|im_end|>", "<|endoftext|>", "[EMPTY_151643]"]}}, timeout=90)
    raw = r.json().get("message", {}).get("content", "")
    i = raw.find("VULNERABILITY:")
    if i > 0: raw = raw[i:]
    v = parse_response(raw).get("VULNERABILITY", "—")
    return not (not v or v.strip() in ("—", "") or v.strip().upper().startswith("NONE"))

for rp in (1.0, 1.1, 1.3):
    tp = sum(1 for c in vuln if ask(c["prompt"], rp))
    fp = sum(1 for c in safe if ask(c["prompt"], rp))
    rec = tp / len(vuln) * 100
    fpr = fp / len(safe) * 100
    print(f"rp={rp}:  재현율={rec:.0f}% (TP {tp}/{len(vuln)})  |  오탐률={fpr:.0f}% (FP {fp}/{len(safe)})")
