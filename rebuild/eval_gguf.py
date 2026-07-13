"""
GGUF/llama.cpp 경로 test 채점 — llama-server(:8080)에 프롬프트를 보내 채점.
eval_test.py와 동일한 파싱·채점 로직 (transformers 의존성 없음).

전제: llama-server -m model-q4km.gguf -ngl 99 가 localhost:8080에 떠 있음.
학습 때 completion이 "<|im_start|>assistant\n" 직후 VULNERABILITY로 시작하도록
학습됐으므로, 같은 지점까지 수동 템플릿으로 프롬프트를 만들어 보낸다(<think> 방지).
"""
from __future__ import annotations

import json
import re
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
rows = [json.loads(l) for l in (ROOT / "data" / "test.jsonl").open()]
OUT_PRED = ROOT / "out" / "test_predictions.jsonl"
OUT_REPORT = ROOT / "out" / "test_report.json"

TMPL = "<|im_start|>user\n{p}<|im_end|>\n<|im_start|>assistant\n"

def infer(prompt: str) -> str:
    body = json.dumps({
        "prompt": TMPL.format(p=prompt),
        "n_predict": 200, "temperature": 0.0,
        "stop": ["<|im_end|>"],
    }).encode()
    req = urllib.request.Request("http://127.0.0.1:8080/completion", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())["content"]

def parse(text: str) -> dict:
    text = re.sub(r"<think>.*?(</think>|$)", "", text, flags=re.S)
    vuln_line = sev_line = ""
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

def run(i_row):
    i, r = i_row
    try:
        raw = infer(r["prompt"])
    except Exception as ex:
        raw = f"ERROR: {ex}"
    if i % 100 == 0:
        print(f"{i}/{len(rows)}", flush=True)
    return {"meta": r["meta"], "raw": raw.strip()[:500], **parse(raw)}

with ThreadPoolExecutor(max_workers=4) as ex:
    preds = list(ex.map(run, enumerate(rows)))

with OUT_PRED.open("w") as f:
    for p in preds:
        f.write(json.dumps(p, ensure_ascii=False) + "\n")

def score(items):
    vg = [p for p in items if p["meta"]["label"] == "vuln"]
    sg = [p for p in items if p["meta"]["label"] == "safe"]
    tp = sum(1 for p in vg if p["label"] == "vuln")
    fp = sum(1 for p in sg if p["label"] == "vuln")
    rec = tp / len(vg) if vg else 0.0
    fpr = fp / len(sg) if sg else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"n": len(items), "n_vuln": len(vg), "n_safe": len(sg),
            "recall": round(rec, 4), "fpr": round(fpr, 4),
            "precision": round(prec, 4), "f1": round(f1, 4),
            "cwe_acc_on_vuln": round(sum(1 for p in vg if p["label"] == "vuln" and p["cwe"] == p["meta"]["cwe_id"]) / len(vg), 4) if vg else 0,
            "sev_acc_on_vuln": round(sum(1 for p in vg if p["label"] == "vuln" and p["severity"] == p["meta"]["severity"]) / len(vg), 4) if vg else 0,
            "parse_fail": sum(1 for p in items if p["label"] == "parse_fail")}

report = {"engine": "llama.cpp Q4_K_M", "overall": score(preds), "by_language": {}, "by_cwe": {}}
by_lang = defaultdict(list)
for p in preds:
    by_lang[p["meta"]["lang_group"]].append(p)
for lang, items in sorted(by_lang.items()):
    report["by_language"][lang] = score(items)
for cwe, _ in Counter(p["meta"]["cwe_id"] for p in preds if p["meta"]["label"] == "vuln").most_common(10):
    items = [p for p in preds if p["meta"]["cwe_id"] == cwe and p["meta"]["label"] == "vuln"]
    report["by_cwe"][cwe] = {"n": len(items),
        "recall": round(sum(1 for p in items if p["label"] == "vuln") / len(items), 4),
        "cwe_acc": round(sum(1 for p in items if p["cwe"] == cwe) / len(items), 4)}

OUT_REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2))
print(json.dumps(report["overall"], indent=2))
print("REPORT_SAVED")
