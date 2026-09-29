"""파인튜닝 전(Ollama gemma:2b) vs 후(TinyLlama LoRA) 벤치마크 비교"""
import json, re, time, urllib.request
from datetime import datetime
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

BASE    = Path(__file__).resolve().parent.parent
LORA    = BASE / "models" / "tinyllama-security-lora"
REPORTS = BASE / "reports"
OUTPUT  = REPORTS / "lora_benchmark.html"
LOSS_LOG = REPORTS / "lora_train_loss.json"

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MDL = "gemma:2b"

# ── 20개 테스트 케이스 ────────────────────────────────────────────────────────
CASES = [
    {"id":  1, "language": "React / Next.js",     "expected_vuln": "XSS",
     "code": 'return <div dangerouslySetInnerHTML={{__html: userInput}} />;'},
    {"id":  2, "language": "React / Next.js",     "expected_vuln": "XSS",
     "code": 'return <a href={`javascript:${userAction}`}>Click</a>;'},
    {"id":  3, "language": "React / Next.js",     "expected_vuln": "Code Injection via eval",
     "code": "eval(searchParams.get('callback'));"},
    {"id":  4, "language": "React / Next.js",     "expected_vuln": "XSS via event handler",
     "code": '<img src={user.avatar} onError={user.fallback} />'},
    {"id":  5, "language": "Node.js / Express",   "expected_vuln": "SQL Injection",
     "code": 'db.query("SELECT * FROM users WHERE id=" + req.params.id);'},
    {"id":  6, "language": "Node.js / Express",   "expected_vuln": "Command Injection",
     "code": "exec(req.body.command);"},
    {"id":  7, "language": "Node.js / Express",   "expected_vuln": "Insecure CORS",
     "code": "res.setHeader('Access-Control-Allow-Origin', '*');"},
    {"id":  8, "language": "Node.js / Express",   "expected_vuln": "Hardcoded Secret",
     "code": "jwt.verify(token, 'hardcoded_secret_key');"},
    {"id":  9, "language": "Java Spring Boot",    "expected_vuln": "SQL Injection",
     "code": 'String query = "SELECT * FROM " + tableName;\nstmt.execute(query);'},
    {"id": 10, "language": "Java Spring Boot",    "expected_vuln": "Command Injection",
     "code": "Runtime.getRuntime().exec(userInput);"},
    {"id": 11, "language": "Java Spring Boot",    "expected_vuln": "Overly Permissive Endpoint",
     "code": '@RequestMapping(value="/**")\npublic ResponseEntity<?> handle(HttpServletRequest req) { ... }'},
    {"id": 12, "language": "Java Spring Boot",    "expected_vuln": "Timing Attack",
     "code": "if (password.equals(inputPassword)) { grantAccess(); }"},
    {"id": 13, "language": "Python",              "expected_vuln": "Insecure Deserialization",
     "code": "import pickle\nobj = pickle.loads(user_data)"},
    {"id": 14, "language": "Python",              "expected_vuln": "Command Injection",
     "code": "import subprocess\nsubprocess.call(user_input, shell=True)"},
    {"id": 15, "language": "Python",              "expected_vuln": "Arbitrary Code Execution via YAML",
     "code": "import yaml\ndata = yaml.load(user_input)  # not safe_load"},
    {"id": 16, "language": "Python",              "expected_vuln": "Command Injection",
     "code": 'import os\nos.system(f"ping {host}")'},
    {"id": 17, "language": "C",                   "expected_vuln": "Format String Attack",
     "code": "printf(user_input);  // user-controlled format string"},
    {"id": 18, "language": "C",                   "expected_vuln": "Buffer Overflow",
     "code": "char buf[64];\nstrcpy(buf, argv[1]);  // no bounds check"},
    {"id": 19, "language": "GitHub Actions YAML", "expected_vuln": "Script Injection via untrusted input",
     "code": "- run: echo ${{ github.event.issue.title }}"},
    {"id": 20, "language": "GitHub Actions YAML", "expected_vuln": "Supply Chain Attack (unpinned action)",
     "code": "- uses: actions/checkout@main  # unpinned version"},
]

# V1 실측 결과 (security_benchmark.py, 기본 프롬프트)
V1_RESULTS = [
    {"id":  1, "detected": True,  "vuln": "Cross-Site Scripting (XSS)",           "elapsed": 1.96},
    {"id":  2, "detected": True,  "vuln": "Cross-Site Scripting (XSS)",           "elapsed": 2.22},
    {"id":  3, "detected": False, "vuln": "Cross-Site Scripting (XSS)",           "elapsed": 5.21},
    {"id":  4, "detected": False, "vuln": "Cross-Origin Request Forgery (CSRF)",  "elapsed": 2.02},
    {"id":  5, "detected": True,  "vuln": "SQL Injection",                        "elapsed": 2.70},
    {"id":  6, "detected": False, "vuln": "Exec vulnerability",                   "elapsed": 6.05},
    {"id":  7, "detected": True,  "vuln": "CORS vulnerability",                   "elapsed": 2.44},
    {"id":  8, "detected": False, "vuln": "JWT Parsing Error",                    "elapsed": 3.71},
    {"id":  9, "detected": True,  "vuln": "SQL Injection",                        "elapsed": 6.26},
    {"id": 10, "detected": False, "vuln": "Cross-site Request Forgery (CSRF)",    "elapsed": 7.77},
    {"id": 11, "detected": False, "vuln": "Cross-site scripting (XSS)",           "elapsed": 6.80},
    {"id": 12, "detected": False, "vuln": "SQL Injection",                        "elapsed": 2.76},
    {"id": 13, "detected": False, "vuln": "Memory leak",                          "elapsed": 1.49},
    {"id": 14, "detected": True,  "vuln": "Shell Injection",                      "elapsed": 1.63},
    {"id": 15, "detected": True,  "vuln": "yaml.load",                            "elapsed": 6.49},
    {"id": 16, "detected": False, "vuln": "Ping vulnerability",                   "elapsed": 2.01},
    {"id": 17, "detected": False, "vuln": "Buffer overflow",                      "elapsed": 4.70},
    {"id": 18, "detected": False, "vuln": "Strcpy without size check",            "elapsed": 4.78},
    {"id": 19, "detected": False, "vuln": "Missing credential management",        "elapsed": 5.19},
    {"id": 20, "detected": False, "vuln": "Unauthorized access",                  "elapsed": 9.20},
]

DETECT_KW = {
    "XSS":                          ["xss", "cross-site scripting", "cwe-79"],
    "Code Injection via eval":      ["injection", "eval", "cwe-78", "cwe-79"],
    "XSS via event handler":        ["xss", "cross-site", "cwe-79", "event"],
    "SQL Injection":                ["sql", "injection", "cwe-89"],
    "Command Injection":            ["command", "injection", "cwe-78", "shell", "exec"],
    "Insecure CORS":                ["cors", "cross-origin", "cwe-346", "origin"],
    "Hardcoded Secret":             ["hardcoded", "credential", "secret", "cwe-798"],
    "Overly Permissive Endpoint":   ["permissive", "access control", "cwe-284", "wildcard"],
    "Timing Attack":                ["timing", "cwe-208", "constant-time"],
    "Insecure Deserialization":     ["deserialization", "pickle", "cwe-502"],
    "Arbitrary Code Execution via YAML": ["yaml", "injection", "cwe-502", "code execution"],
    "Format String Attack":         ["format", "cwe-134", "format string"],
    "Buffer Overflow":              ["buffer", "overflow", "cwe-120", "strcpy"],
    "Script Injection via untrusted input": ["injection", "script", "cwe-116", "untrusted"],
    "Supply Chain Attack (unpinned action)": ["supply chain", "unpinned", "cwe-116", "pin"],
}
SEVERITY_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}
LANG_COLOR = {
    "React / Next.js":     "#06b6d4", "Node.js / Express":   "#22c55e",
    "Java Spring Boot":    "#f97316", "Python":               "#a855f7",
    "C":                   "#64748b", "GitHub Actions YAML":  "#ec4899",
}

PROMPT_TMPL = ("Analyze this {language} code for security vulnerabilities:\n\n"
               "{code}\n\nVULN_TYPE:")


def is_detected(text: str, expected: str) -> bool:
    keywords = DETECT_KW.get(expected, expected.lower().split())
    t = text.lower()
    return any(k.lower() in t for k in keywords)


def ollama_query(language: str, code: str) -> tuple[str, float]:
    prompt  = PROMPT_TMPL.format(language=language, code=code)
    payload = json.dumps({"model": OLLAMA_MDL, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(OLLAMA_URL, data=payload,
                                 headers={"Content-Type": "application/json"}, method="POST")
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = json.loads(resp.read())
    return body["response"], round(time.perf_counter() - t0, 2)


def lora_query(tokenizer, model, language: str, code: str, device: str) -> tuple[str, float]:
    prompt = PROMPT_TMPL.format(language=language, code=code)
    inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=400)
    inputs = {k: v.to(device) for k, v in inputs.items()}
    t0 = time.perf_counter()
    with torch.no_grad():
        out = model.generate(
            **inputs, max_new_tokens=100, do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    elapsed = round(time.perf_counter() - t0, 2)
    gen = out[0][inputs["input_ids"].shape[1]:]
    return tokenizer.decode(gen, skip_special_tokens=True).strip(), elapsed


def esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_html(pre_results, post_results, loss_history):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    pre_det  = sum(1 for r in pre_results  if r["detected"])
    post_det = sum(1 for r in post_results if r["detected"])
    n = len(CASES)
    pre_pct  = round(pre_det  / n * 100, 1)
    post_pct = round(post_det / n * 100, 1)
    delta_p  = round(post_pct - pre_pct, 1)
    pre_avg  = round(sum(r["elapsed"] for r in pre_results)  / n, 2)
    post_avg = round(sum(r["elapsed"] for r in post_results) / n, 2)

    det_color = "#22c55e" if post_pct >= 50 else ("#eab308" if post_pct >= 30 else "#dc2626")
    dp_color  = "#22c55e" if delta_p >= 0 else "#ef4444"
    dp_str    = f"+{delta_p}%p" if delta_p >= 0 else f"{delta_p}%p"

    # 손실 차트 데이터
    loss_steps  = [e["step"]  for e in loss_history if "loss" in e]
    loss_vals   = [float(e["loss"]) for e in loss_history if "loss" in e]

    # 언어별 테이블
    langs = list(dict.fromkeys(c["language"] for c in CASES))
    lang_rows = ""
    for lang in langs:
        ids   = [c["id"] for c in CASES if c["language"] == lang]
        pre_ok  = sum(1 for r in pre_results  if r["id"] in ids and r["detected"])
        post_ok = sum(1 for r in post_results if r["id"] in ids and r["detected"])
        nm    = len(ids)
        diff  = post_ok - pre_ok
        arrow_c = "#22c55e" if diff > 0 else ("#ef4444" if diff < 0 else "#94a3b8")
        arr   = f"↑+{diff}" if diff > 0 else (f"↓{diff}" if diff < 0 else "=")
        color = LANG_COLOR.get(lang, "#94a3b8")
        lang_rows += f"""<tr>
          <td><span class="dot" style="background:{color};"></span>{esc(lang)}</td>
          <td class="c">{pre_ok}/{nm}</td><td class="c">{post_ok}/{nm}</td>
          <td class="c" style="color:{arrow_c};font-weight:700;">{arr}</td></tr>"""

    # 케이스 카드
    pre_map = {r["id"]: r for r in pre_results}
    cards = ""
    for case, post in zip(CASES, post_results):
        pre   = pre_map[case["id"]]
        color = LANG_COLOR.get(case["language"], "#94a3b8")
        def tick(ok): return ('<span class="tok">✓</span>' if ok else '<span class="tmiss">✗</span>')
        cards += f"""
        <div class="card">
          <div class="chead" style="border-left:4px solid {color};">
            <span class="cnum">#{case['id']}</span>
            <span class="ctag" style="background:{color}20;color:{color};">{esc(case['language'])}</span>
            <span class="cexp">Expected: <strong>{esc(case['expected_vuln'])}</strong></span>
          </div>
          <div class="ccode"><pre>{esc(case['code'])}</pre></div>
          <div class="cversus">
            <div class="cver pre-ver">
              <div class="vlab">Gemma 2B (Ollama · pre-LoRA)</div>
              <div class="vtxt">{esc(pre['vuln'])}</div>
              <div class="vmeta">{tick(pre['detected'])} &nbsp; {pre['elapsed']}s</div>
            </div>
            <div class="vsep">→</div>
            <div class="cver post-ver">
              <div class="vlab">TinyLlama + LoRA (post-tuning)</div>
              <div class="vtxt">{esc(post['vuln'])}</div>
              <div class="vmeta">{tick(post['detected'])} &nbsp; {post['elapsed']}s</div>
            </div>
          </div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LoRA Benchmark — ScanOps</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f4f8;color:#1e293b;padding:24px}}
  h1{{font-size:1.55rem;font-weight:800;margin-bottom:4px}}
  .sub{{color:#64748b;font-size:.85rem;margin-bottom:24px}}
  code{{font-family:'JetBrains Mono','Fira Code',monospace;font-size:.82em;
        background:#f1f5f9;padding:1px 5px;border-radius:4px}}

  .heroes{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px}}
  .hero{{border-radius:12px;padding:18px 22px;flex:1;min-width:130px;color:#fff}}
  .hl{{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;opacity:.7}}
  .hv{{font-size:2rem;font-weight:800;margin-top:2px}}
  .hs{{font-size:.72rem;opacity:.6;margin-top:2px}}

  .charts{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:22px}}
  .cbox{{background:#fff;border-radius:12px;padding:20px;flex:1;min-width:240px;
         box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .cbox h2{{font-size:.88rem;font-weight:700;color:#334155;margin-bottom:12px}}
  canvas{{max-height:220px}}

  .stitle{{font-size:.8rem;font-weight:700;color:#475569;text-transform:uppercase;
           letter-spacing:.05em;margin-bottom:10px}}
  .tw{{background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08);
       margin-bottom:22px;overflow-x:auto}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem}}
  th{{background:#f8fafc;padding:9px 14px;text-align:left;font-size:.7rem;font-weight:700;
      text-transform:uppercase;letter-spacing:.05em;color:#64748b;border-bottom:1px solid #e2e8f0}}
  td{{padding:10px 14px;border-bottom:1px solid #f1f5f9}}
  tr:last-child td{{border-bottom:none}}
  .c{{text-align:center}}
  .dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;vertical-align:middle}}

  .card{{background:#fff;border-radius:12px;margin-bottom:14px;overflow:hidden;
         box-shadow:0 1px 4px rgba(0,0,0,.07)}}
  .chead{{display:flex;align-items:center;gap:8px;padding:9px 14px;
          background:#f8fafc;border-bottom:1px solid #e2e8f0;flex-wrap:wrap}}
  .cnum{{font-weight:800;font-size:.78rem;color:#64748b}}
  .ctag{{font-size:.7rem;font-weight:700;padding:2px 7px;border-radius:999px}}
  .cexp{{font-size:.78rem;color:#475569;flex:1}}
  .ccode{{background:#0f172a;padding:10px 14px;overflow-x:auto}}
  .ccode pre{{color:#e2e8f0;font-family:'JetBrains Mono','Fira Code',monospace;
              font-size:.77rem;line-height:1.5;white-space:pre-wrap;word-break:break-word}}
  .cversus{{display:flex;align-items:stretch}}
  .cver{{flex:1;padding:12px 14px}}
  .pre-ver{{background:#fffbeb;border-right:1px solid #fde68a}}
  .post-ver{{background:#f0fdf4}}
  .vsep{{display:flex;align-items:center;padding:0 10px;color:#94a3b8;
         font-size:.85rem;font-weight:700;background:#f8fafc;
         border-left:1px solid #e2e8f0;border-right:1px solid #e2e8f0}}
  .vlab{{font-size:.68rem;font-weight:700;text-transform:uppercase;
         letter-spacing:.05em;color:#94a3b8;margin-bottom:5px}}
  .vtxt{{font-size:.82rem;color:#334155;margin-bottom:5px;line-height:1.4}}
  .vmeta{{font-size:.75rem;color:#64748b}}
  .tok{{color:#16a34a;font-weight:800}}
  .tmiss{{color:#dc2626;font-weight:800}}

  @media(max-width:640px){{
    .heroes,.charts{{flex-direction:column}}
    .cversus{{flex-direction:column}}
    .vsep{{padding:4px;border:none;border-top:1px solid #e2e8f0;border-bottom:1px solid #e2e8f0}}
    .pre-ver{{border-right:none;border-bottom:1px solid #fde68a}}
  }}
</style>
</head>
<body>
<h1>LoRA Fine-tuning Benchmark</h1>
<p class="sub">ScanOps · {now} · Pre: <code>{OLLAMA_MDL}</code> via Ollama · Post: <code>TinyLlama-1.1B + LoRA</code> (50 examples, 3 epochs)</p>

<div class="heroes">
  <div class="hero" style="background:#dc2626;">
    <div class="hl">Pre-LoRA (Gemma 2B)</div>
    <div class="hv">{pre_pct}%</div>
    <div class="hs">{pre_det}/{n} detected</div>
  </div>
  <div class="hero" style="background:{det_color};">
    <div class="hl">Post-LoRA (TinyLlama)</div>
    <div class="hv">{post_pct}%</div>
    <div class="hs">{post_det}/{n} detected</div>
  </div>
  <div class="hero" style="background:{dp_color};">
    <div class="hl">Detection Change</div>
    <div class="hv">{dp_str}</div>
    <div class="hs">percentage points</div>
  </div>
  <div class="hero" style="background:#334155;">
    <div class="hl">Avg Inference Time</div>
    <div class="hv">{post_avg}s</div>
    <div class="hs">Pre: {pre_avg}s</div>
  </div>
  <div class="hero" style="background:#7c3aed;">
    <div class="hl">Final Training Loss</div>
    <div class="hv">{loss_vals[-1]:.3f}</div>
    <div class="hs">3 epochs · 50 examples</div>
  </div>
</div>

<div class="charts">
  <div class="cbox">
    <h2>Training Loss Curve</h2>
    <canvas id="lossChart"></canvas>
  </div>
  <div class="cbox">
    <h2>Detection Rate by Language</h2>
    <canvas id="detChart"></canvas>
  </div>
</div>

<p class="stitle">Detection by Language</p>
<div class="tw">
  <table>
    <thead><tr><th>Language</th><th class="c">Pre-LoRA</th><th class="c">Post-LoRA</th><th class="c">Change</th></tr></thead>
    <tbody>{lang_rows}</tbody>
  </table>
</div>

<p class="stitle">Case-by-Case</p>
{cards}

<script>
new Chart(document.getElementById('lossChart'), {{
  type: 'line',
  data: {{
    labels: {json.dumps(loss_steps)},
    datasets: [{{ label: 'Train Loss', data: {json.dumps(loss_vals)},
      borderColor: '#7c3aed', backgroundColor: 'rgba(124,58,237,.1)',
      tension: 0.3, fill: true, pointRadius: 4 }}]
  }},
  options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }},
    scales: {{ y: {{ beginAtZero: false }} }} }}
}});

const langs = {json.dumps(langs)};
const preD  = {json.dumps([sum(1 for r in pre_results  if r['id'] in [c['id'] for c in CASES if c['language']==l] and r['detected']) for l in langs])};
const postD = {json.dumps([sum(1 for r in post_results if r['id'] in [c['id'] for c in CASES if c['language']==l] and r['detected']) for l in langs])};
const lc    = {json.dumps([LANG_COLOR.get(l, '#94a3b8') for l in langs])};
new Chart(document.getElementById('detChart'), {{
  type: 'bar',
  data: {{ labels: langs,
    datasets: [
      {{ label:'Pre-LoRA',  data:preD,  backgroundColor:'rgba(220,38,38,.6)',
         borderRadius:4, borderSkipped:false }},
      {{ label:'Post-LoRA', data:postD, backgroundColor:'rgba(34,197,94,.75)',
         borderRadius:4, borderSkipped:false }},
    ]}},
  options: {{ responsive: true, plugins: {{ legend: {{ position:'top' }} }},
    scales: {{ y: {{ beginAtZero:true, max:{max(sum(1 for c in CASES if c['language']==l) for l in langs)} }},
               x: {{ grid: {{ display:false }} }} }} }}
}});
</script>
</body>
</html>"""


def main():
    REPORTS.mkdir(exist_ok=True)

    # 손실 로그 로드
    with open(LOSS_LOG) as f:
        loss_history = json.load(f)

    # ── A. Pre-LoRA: Ollama gemma:2b 재실행 ──────────────────────────
    print(f"{'─'*55}")
    print(f"[A] Pre-LoRA: Ollama {OLLAMA_MDL}")
    print(f"{'─'*55}")
    pre_results = []
    for case in CASES:
        print(f"  [{case['id']:02d}/20] {case['expected_vuln'][:40]}", end=" ... ", flush=True)
        resp, elapsed = ollama_query(case["language"], case["code"])
        # 첫 줄 = VULN_TYPE 값
        vuln = resp.strip().split("\n")[0][:80]
        ok   = is_detected(vuln, case["expected_vuln"])
        pre_results.append({**case, "vuln": vuln, "elapsed": elapsed, "detected": ok})
        print(f"{'✓' if ok else '✗'} {elapsed}s")

    pre_det = sum(1 for r in pre_results if r["detected"])
    print(f"Pre-LoRA 탐지율: {pre_det}/20 ({round(pre_det/20*100,1)}%)\n")

    # ── B. Post-LoRA: TinyLlama + LoRA ────────────────────────────────
    print(f"{'─'*55}")
    print(f"[B] Post-LoRA: TinyLlama + LoRA")
    print(f"{'─'*55}")

    device = "mps" if torch.backends.mps.is_available() else "cpu"
    print(f"  device: {device}")
    tokenizer = AutoTokenizer.from_pretrained(str(LORA))
    base = AutoModelForCausalLM.from_pretrained(
        "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
        torch_dtype=torch.float16 if device == "mps" else torch.float32,
        low_cpu_mem_usage=True,
    )
    model = PeftModel.from_pretrained(base, str(LORA))
    model = model.to(device)
    model.eval()

    post_results = []
    for case in CASES:
        print(f"  [{case['id']:02d}/20] {case['expected_vuln'][:40]}", end=" ... ", flush=True)
        resp, elapsed = lora_query(tokenizer, model, case["language"], case["code"], device)
        vuln = resp.strip().split("\n")[0][:80]
        ok   = is_detected(vuln, case["expected_vuln"])
        post_results.append({**case, "vuln": vuln, "elapsed": elapsed, "detected": ok})
        print(f"{'✓' if ok else '✗'} {elapsed}s  |  {vuln[:50]}")

    post_det = sum(1 for r in post_results if r["detected"])
    pre_avg  = round(sum(r["elapsed"] for r in pre_results)  / 20, 2)
    post_avg = round(sum(r["elapsed"] for r in post_results) / 20, 2)

    # ── HTML 저장 ──────────────────────────────────────────────────────
    html = build_html(pre_results, post_results, loss_history)
    OUTPUT.write_text(html, encoding="utf-8")

    print(f"\n{'─'*55}")
    print(f"Pre-LoRA  탐지율: {pre_det}/20 ({round(pre_det/20*100,1)}%)  avg {pre_avg}s")
    print(f"Post-LoRA 탐지율: {post_det}/20 ({round(post_det/20*100,1)}%)  avg {post_avg}s")
    print(f"HTML 저장: {OUTPUT}")


if __name__ == "__main__":
    main()
