"""
ScanOps 재구축 — Claude / Grok API 비교 채점 (로컬 실행, GPU 불필요)
====================================================================
우리 모델과 동일 조건 비교:
  - 같은 test.jsonl 1,197건, 같은 prompt(서식 안내 포함)
  - eval_test.py와 동일한 parse()·score() 로직 (복사)
  - 다른 것은 "누가 답을 생성했나"(Sonnet 5 / Grok)뿐

Claude: Anthropic SDK (claude-sonnet-5)
Grok:   xAI OpenAI-호환 엔드포인트 (grok-4)

환경변수: ANTHROPIC_API_KEY, XAI_API_KEY (scanops-model/.env)
실행:  .venv/bin/python rebuild/compare_apis.py claude
       .venv/bin/python rebuild/compare_apis.py grok
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
rows = [json.loads(l) for l in (ROOT / "data" / "test.jsonl").open()]

# .env 로드 (간단 파서)
for line in (ROOT.parent / ".env").read_text().splitlines():
    if "=" in line and not line.strip().startswith("#"):
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())

SYSTEM = ("You are a security code analyzer. Analyze the given code and respond "
          "ONLY in the exact 4-line format requested. Do not add explanation before or after.")

# ── 파서·채점: eval_test.py와 동일 ───────────────────────────────────────────
def parse(text: str) -> dict:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
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

def score(items: list[dict]) -> dict:
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

# ── 백엔드 호출 ──────────────────────────────────────────────────────────────
def call_claude(prompt: str) -> str:
    import anthropic
    client = anthropic.Anthropic()
    r = client.messages.create(
        model="claude-sonnet-5", max_tokens=400,
        system=SYSTEM, messages=[{"role": "user", "content": prompt}],
    )
    return "".join(b.text for b in r.content if b.type == "text")

def call_grok(prompt: str) -> str:
    body = json.dumps({
        "model": "grok-4",
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": prompt}],
        "max_tokens": 400, "temperature": 0,
    }).encode()
    req = urllib.request.Request(
        "https://api.x.ai/v1/chat/completions", data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {os.environ['XAI_API_KEY']}"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())["choices"][0]["message"]["content"]

BACKENDS = {"claude": ("claude-sonnet-5", call_claude),
            "grok": ("grok-4", call_grok)}

def main() -> None:
    which = sys.argv[1] if len(sys.argv) > 1 else "claude"
    model_name, fn = BACKENDS[which]
    print(f"{which} ({model_name}) — test {len(rows)}건 비교 시작")

    def run(i_row):
        i, r = i_row
        try:
            raw = fn(r["prompt"])
        except Exception as ex:
            raw = f"ERROR: {ex}"
        if i % 100 == 0:
            print(f"{i}/{len(rows)}", flush=True)
        return {"meta": r["meta"], "raw": raw.strip()[:500], **parse(raw)}

    with ThreadPoolExecutor(max_workers=8) as ex:
        preds = list(ex.map(run, enumerate(rows)))

    out_pred = ROOT / "out" / f"compare_{which}_predictions.jsonl"
    with out_pred.open("w") as f:
        for p in preds:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    report = {"engine": model_name, "overall": score(preds),
              "by_language": {}, "by_cwe": {}}
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

    (ROOT / "out" / f"compare_{which}_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps(report["overall"], indent=2))
    print(f"저장: out/compare_{which}_report.json")

if __name__ == "__main__":
    main()
