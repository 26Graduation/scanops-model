import json
import re
import time
import urllib.request
from datetime import datetime
from pathlib import Path

API_URL = "http://localhost:11434/api/generate"
MODEL   = "gemma:2b"
REPORTS = Path(__file__).resolve().parent.parent / "reports"
OUTPUT  = REPORTS / "security_benchmark_v2.html"

# ── 20개 테스트 케이스 (v1과 동일) ─────────────────────────────────────────
CASES = [
    {"id":  1, "language": "React / Next.js",       "expected_vuln": "XSS",
     "code": 'return <div dangerouslySetInnerHTML={{__html: userInput}} />;'},
    {"id":  2, "language": "React / Next.js",       "expected_vuln": "XSS",
     "code": 'return <a href={`javascript:${userAction}`}>Click</a>;'},
    {"id":  3, "language": "React / Next.js",       "expected_vuln": "Code Injection via eval",
     "code": "eval(searchParams.get('callback'));"},
    {"id":  4, "language": "React / Next.js",       "expected_vuln": "XSS via event handler",
     "code": '<img src={user.avatar} onError={user.fallback} />'},
    {"id":  5, "language": "Node.js / Express",     "expected_vuln": "SQL Injection",
     "code": 'db.query("SELECT * FROM users WHERE id=" + req.params.id);'},
    {"id":  6, "language": "Node.js / Express",     "expected_vuln": "Command Injection",
     "code": "exec(req.body.command);"},
    {"id":  7, "language": "Node.js / Express",     "expected_vuln": "Insecure CORS",
     "code": "res.setHeader('Access-Control-Allow-Origin', '*');"},
    {"id":  8, "language": "Node.js / Express",     "expected_vuln": "Hardcoded Secret",
     "code": "jwt.verify(token, 'hardcoded_secret_key');"},
    {"id":  9, "language": "Java Spring Boot",      "expected_vuln": "SQL Injection",
     "code": 'String query = "SELECT * FROM " + tableName;\nstmt.execute(query);'},
    {"id": 10, "language": "Java Spring Boot",      "expected_vuln": "Command Injection",
     "code": "Runtime.getRuntime().exec(userInput);"},
    {"id": 11, "language": "Java Spring Boot",      "expected_vuln": "Overly Permissive Endpoint",
     "code": '@RequestMapping(value="/**")\npublic ResponseEntity<?> handle(HttpServletRequest req) { ... }'},
    {"id": 12, "language": "Java Spring Boot",      "expected_vuln": "Timing Attack",
     "code": "if (password.equals(inputPassword)) { grantAccess(); }"},
    {"id": 13, "language": "Python",                "expected_vuln": "Insecure Deserialization",
     "code": "import pickle\nobj = pickle.loads(user_data)"},
    {"id": 14, "language": "Python",                "expected_vuln": "Command Injection",
     "code": "import subprocess\nsubprocess.call(user_input, shell=True)"},
    {"id": 15, "language": "Python",                "expected_vuln": "Arbitrary Code Execution via YAML",
     "code": "import yaml\ndata = yaml.load(user_input)  # not safe_load"},
    {"id": 16, "language": "Python",                "expected_vuln": "Command Injection",
     "code": 'import os\nos.system(f"ping {host}")'},
    {"id": 17, "language": "C",                     "expected_vuln": "Format String Attack",
     "code": "printf(user_input);  // user-controlled format string"},
    {"id": 18, "language": "C",                     "expected_vuln": "Buffer Overflow",
     "code": "char buf[64];\nstrcpy(buf, argv[1]);  // no bounds check"},
    {"id": 19, "language": "GitHub Actions YAML",   "expected_vuln": "Script Injection via untrusted input",
     "code": "- run: echo ${{ github.event.issue.title }}"},
    {"id": 20, "language": "GitHub Actions YAML",   "expected_vuln": "Supply Chain Attack (unpinned action)",
     "code": "- uses: actions/checkout@main  # unpinned version"},
]

# ── V1 실측 결과 (hardcode) ───────────────────────────────────────────────────
V1_RESULTS = [
    {"id":  1, "detected": True,  "vuln": "Cross-Site Scripting (XSS)",              "severity": "CRITICAL", "elapsed": 1.96},
    {"id":  2, "detected": True,  "vuln": "Cross-Site Scripting (XSS)",              "severity": "HIGH",     "elapsed": 2.22},
    {"id":  3, "detected": False, "vuln": "Cross-Site Scripting (XSS)",              "severity": "HIGH",     "elapsed": 5.21},
    {"id":  4, "detected": False, "vuln": "Cross-Origin Request Forgery (CSRF)",     "severity": "HIGH",     "elapsed": 2.02},
    {"id":  5, "detected": True,  "vuln": "SQL Injection",                           "severity": "CRITICAL", "elapsed": 2.70},
    {"id":  6, "detected": False, "vuln": "Exec vulnerability",                      "severity": "CRITICAL", "elapsed": 6.05},
    {"id":  7, "detected": True,  "vuln": "Cross-Origin Resource Sharing (CORS)",    "severity": "CRITICAL", "elapsed": 2.44},
    {"id":  8, "detected": False, "vuln": "JWT Parsing Error",                       "severity": "HIGH",     "elapsed": 3.71},
    {"id":  9, "detected": True,  "vuln": "SQL Injection",                           "severity": "HIGH",     "elapsed": 6.26},
    {"id": 10, "detected": False, "vuln": "Cross-site Request Forgery (CSRF)",       "severity": "HIGH",     "elapsed": 7.77},
    {"id": 11, "detected": False, "vuln": "Cross-site scripting (XSS)",              "severity": "HIGH",     "elapsed": 6.80},
    {"id": 12, "detected": False, "vuln": "SQL Injection",                           "severity": "HIGH",     "elapsed": 2.76},
    {"id": 13, "detected": False, "vuln": "Memory leak",                             "severity": "HIGH",     "elapsed": 1.49},
    {"id": 14, "detected": True,  "vuln": "Shell Injection",                         "severity": "CRITICAL", "elapsed": 1.63},
    {"id": 15, "detected": True,  "vuln": "yaml.load",                               "severity": "HIGH",     "elapsed": 6.49},
    {"id": 16, "detected": False, "vuln": "Ping vulnerability",                      "severity": "HIGH",     "elapsed": 2.01},
    {"id": 17, "detected": False, "vuln": "Buffer overflow",                         "severity": "HIGH",     "elapsed": 4.70},
    {"id": 18, "detected": False, "vuln": "Strcpy without size check",               "severity": "HIGH",     "elapsed": 4.78},
    {"id": 19, "detected": False, "vuln": "Missing credential management",           "severity": "HIGH",     "elapsed": 5.19},
    {"id": 20, "detected": False, "vuln": "Unauthorized access to GitHub repository","severity": "CRITICAL", "elapsed": 9.20},
]

# ── 탐지 판정 키워드 맵 ──────────────────────────────────────────────────────
DETECT_MAP = {
    "XSS":                    ["XSS", "CWE-79", "Cross-Site Scripting"],
    "SQL Injection":          ["SQL", "CWE-89", "Injection"],
    "Command Injection":      ["Command", "CWE-78", "Injection", "Shell"],
    "Code Injection via eval":["Injection", "eval", "CWE-78", "CWE-79"],
    "XSS via event handler":  ["XSS", "CWE-79", "Cross-Site Scripting"],
    "Insecure CORS":          ["CORS", "CWE-346", "Cross-Origin", "Origin"],
    "Hardcoded Secret":       ["Hardcoded", "CWE-798", "Credential", "Secret"],
    "Overly Permissive Endpoint": ["Permissive", "Authorization", "Access Control", "CWE-284", "Wildcard"],
    "Timing Attack":          ["Timing", "CWE-208", "constant-time", "timing"],
    "Insecure Deserialization": ["Deserialization", "CWE-502", "pickle", "Deserializ"],
    "Arbitrary Code Execution via YAML": ["YAML", "CWE-502", "Injection", "yaml.load"],
    "Format String Attack":   ["Format", "CWE-134", "format string"],
    "Buffer Overflow":        ["Buffer", "CWE-120", "Overflow", "strcpy"],
    "Script Injection via untrusted input": ["Injection", "CWE-116", "Script", "untrusted"],
    "Supply Chain Attack (unpinned action)": ["Supply", "unpinned", "CWE-116", "Chain", "pin"],
}

PROMPT_V2 = """\
You are a security code auditor specialized in OWASP Top 10 and CWE classifications.

Analyze the following {language} code snippet for security vulnerabilities.
Focus ONLY on these vulnerability classes:
- CWE-89: SQL Injection
- CWE-79: XSS (Cross-Site Scripting)
- CWE-78: OS Command Injection
- CWE-134: Format String Attack
- CWE-502: Insecure Deserialization
- CWE-798: Hardcoded Credentials
- CWE-352: CSRF
- CWE-120: Buffer Overflow
- CWE-601: Open Redirect
- CWE-116: Improper Encoding (GitHub Actions Injection)

Code:
{code}

You MUST respond in EXACTLY this format, nothing else:
VULN_TYPE: [CWE ID and name]
SEVERITY: [CRITICAL or HIGH or MEDIUM or LOW]
ATTACK: [one sentence attack scenario]
FIX: [fixed code only, no explanation]\
"""

SEVERITY_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}
LANG_COLOR = {
    "React / Next.js":     "#06b6d4",
    "Node.js / Express":   "#22c55e",
    "Java Spring Boot":    "#f97316",
    "Python":              "#a855f7",
    "C":                   "#64748b",
    "GitHub Actions YAML": "#ec4899",
}


def query_model(language: str, code: str) -> tuple[str, float]:
    prompt  = PROMPT_V2.format(language=language, code=code)
    payload = json.dumps({"model": MODEL, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(
        API_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = json.loads(resp.read())
    return body["response"], round(time.perf_counter() - t0, 2)


def parse_v2(text: str) -> dict:
    fields = {}
    # VULN_TYPE 전용 패턴 추가, 나머지는 v1과 동일
    key_patterns = {
        "VULN_TYPE": r"vuln(?:_type)?",
        "SEVERITY":  r"severity",
        "ATTACK":    r"attack",
        "FIX":       r"fix",
    }
    for canonical, pat in key_patterns.items():
        m = re.search(rf"^\*{{0,2}}{pat}\*{{0,2}}:[ \t]*(.+)", text, re.MULTILINE | re.IGNORECASE)
        fields[canonical] = re.sub(r"\*+", "", m.group(1)).strip() if m else "—"

    # FIX 여러 줄 처리
    m_fix = re.search(r"^\*{0,2}fix\*{0,2}:[ \t]*([\s\S]+)", text, re.MULTILINE | re.IGNORECASE)
    if m_fix:
        raw = m_fix.group(1).strip()
        raw = re.sub(r"^```[^\n]*\n", "", raw).rstrip("`").strip()
        fields["FIX"] = raw
    return fields


def is_detected(vuln_type_text: str, expected: str) -> bool:
    keywords = DETECT_MAP.get(expected, expected.split())
    t = vuln_type_text.lower()
    return any(k.lower() in t for k in keywords)


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ── HTML ──────────────────────────────────────────────────────────────────────

def build_html(v2: list[dict]) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    v1_det   = sum(1 for r in V1_RESULTS if r["detected"])
    v2_det   = sum(1 for r in v2 if r["detected"])
    v1_pct   = round(v1_det / len(V1_RESULTS) * 100, 1)
    v2_pct   = round(v2_det / len(v2) * 100, 1)
    delta_p  = round(v2_pct - v1_pct, 1)
    v1_avg   = round(sum(r["elapsed"] for r in V1_RESULTS) / len(V1_RESULTS), 2)
    v2_avg   = round(sum(r["elapsed"] for r in v2) / len(v2), 2)
    delta_t  = round(v2_avg - v1_avg, 2)

    det_color = "#22c55e" if v2_pct >= 50 else ("#eab308" if v2_pct >= 30 else "#ef4444")
    delta_color = "#22c55e" if delta_p > 0 else "#ef4444"
    time_color  = "#22c55e" if delta_t <= 0 else "#ef4444"
    delta_t_str = f"+{delta_t}s" if delta_t > 0 else f"{delta_t}s"
    delta_p_str = f"+{delta_p}%p" if delta_p >= 0 else f"{delta_p}%p"

    # ── 언어별 요약 테이블 ──
    langs = list(dict.fromkeys(c["language"] for c in CASES))
    lang_rows = ""
    for lang in langs:
        ids   = [c["id"] for c in CASES if c["language"] == lang]
        v1_ok = sum(1 for r in V1_RESULTS if r["id"] in ids and r["detected"])
        v2_ok = sum(1 for r in v2 if r["id"] in ids and r["detected"])
        n     = len(ids)
        arrow = "↑" if v2_ok > v1_ok else ("↓" if v2_ok < v1_ok else "=")
        arr_c = "#22c55e" if v2_ok > v1_ok else ("#ef4444" if v2_ok < v1_ok else "#94a3b8")
        color = LANG_COLOR.get(lang, "#94a3b8")
        lang_rows += f"""
        <tr>
          <td><span class="lang-dot" style="background:{color};"></span>{esc(lang)}</td>
          <td class="center">{v1_ok}/{n}</td>
          <td class="center">{v2_ok}/{n}</td>
          <td class="center" style="color:{arr_c};font-weight:700;">{arrow} {v2_ok - v1_ok:+d}</td>
        </tr>"""

    # ── 케이스 카드 ──
    v1_map = {r["id"]: r for r in V1_RESULTS}
    cards  = ""
    for case, r2 in zip(CASES, v2):
        r1   = v1_map[case["id"]]
        color = LANG_COLOR.get(case["language"], "#94a3b8")
        sc2   = SEVERITY_COLOR.get(r2["parsed"].get("SEVERITY", "").upper(), "#94a3b8")
        sc1   = SEVERITY_COLOR.get(r1["severity"], "#94a3b8")

        def tick(ok): return ('<span class="tick ok">✓ Detected</span>' if ok
                              else '<span class="tick miss">✗ Missed</span>')

        fix_esc = esc(r2["parsed"].get("FIX", "—"))

        cards += f"""
        <div class="card">
          <div class="card-header" style="border-left:4px solid {color};">
            <span class="case-num">#{case['id']}</span>
            <span class="lang-tag" style="background:{color}20;color:{color};">{esc(case['language'])}</span>
            <span class="expected">Expected: <strong>{esc(case['expected_vuln'])}</strong></span>
          </div>
          <div class="code-block"><pre>{esc(case['code'])}</pre></div>
          <div class="versus">
            <div class="ver v1">
              <div class="ver-label">V1 — Basic Prompt</div>
              <div class="ver-row"><span class="field-lbl">VULN</span><span>{esc(r1['vuln'])}</span></div>
              <div class="ver-row"><span class="field-lbl">SEV</span>
                <span class="sev-badge" style="background:{sc1};">{r1['severity']}</span>
                <span class="elapsed">{r1['elapsed']}s</span></div>
              <div class="ver-foot">{tick(r1['detected'])}</div>
            </div>
            <div class="divider">vs</div>
            <div class="ver v2">
              <div class="ver-label">V2 — OWASP/CWE Prompt</div>
              <div class="ver-row"><span class="field-lbl">VULN</span><span>{esc(r2['parsed'].get('VULN_TYPE','—'))}</span></div>
              <div class="ver-row"><span class="field-lbl">SEV</span>
                <span class="sev-badge" style="background:{sc2};">{r2['parsed'].get('SEVERITY','—')}</span>
                <span class="elapsed">{r2['elapsed']}s</span></div>
              <div class="ver-foot">{tick(r2['detected'])}</div>
            </div>
          </div>
          <div class="fix-section">
            <div class="fix-label">V2 FIX</div>
            <pre class="fix-block">{fix_esc}</pre>
          </div>
        </div>"""

    # ── 차트 데이터 ──
    chart_labels  = json.dumps(langs)
    chart_v1      = json.dumps([
        sum(1 for r in V1_RESULTS if r["id"] in [c["id"] for c in CASES if c["language"] == l] and r["detected"])
        for l in langs])
    chart_v2      = json.dumps([
        sum(1 for r in v2 if r["id"] in [c["id"] for c in CASES if c["language"] == l] and r["detected"])
        for l in langs])
    chart_max     = json.dumps([sum(1 for c in CASES if c["language"] == l) for l in langs])

    lang_avg_times = []
    for l in langs:
        rows = [r for r, c in zip(v2, CASES) if c["language"] == l]
        lang_avg_times.append(round(sum(r["elapsed"] for r in rows) / len(rows), 2) if rows else 0)
    chart_time_data = json.dumps(lang_avg_times)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Benchmark V1 vs V2 — ScanOps</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f4f8;color:#1e293b;padding:24px}}
  h1{{font-size:1.55rem;font-weight:800;margin-bottom:4px}}
  .sub{{color:#64748b;font-size:.85rem;margin-bottom:24px}}
  code{{font-family:'JetBrains Mono','Fira Code',monospace;font-size:.82em;
        background:#f1f5f9;padding:1px 5px;border-radius:4px}}

  /* Hero summary */
  .heroes{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
  .hero{{border-radius:12px;padding:18px 24px;flex:1;min-width:140px;color:#fff}}
  .hero-lbl{{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;opacity:.75}}
  .hero-val{{font-size:2rem;font-weight:800;margin-top:2px}}
  .hero-sub{{font-size:.72rem;opacity:.65;margin-top:2px}}

  /* Lang table */
  .section-title{{font-size:.9rem;font-weight:700;color:#475569;
                  text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px}}
  .lang-table-wrap{{background:#fff;border-radius:12px;overflow:hidden;
                    box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:24px}}
  table{{width:100%;border-collapse:collapse;font-size:.88rem}}
  th{{background:#f8fafc;padding:10px 16px;text-align:left;font-size:.72rem;
      font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:#64748b;
      border-bottom:1px solid #e2e8f0}}
  td{{padding:11px 16px;border-bottom:1px solid #f1f5f9}}
  tr:last-child td{{border-bottom:none}}
  .center{{text-align:center}}
  .lang-dot{{display:inline-block;width:8px;height:8px;border-radius:50%;
             margin-right:8px;vertical-align:middle}}

  /* Charts */
  .charts{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}}
  .chart-box{{background:#fff;border-radius:12px;padding:20px;flex:1;min-width:260px;
              box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .chart-box h2{{font-size:.88rem;font-weight:600;color:#334155;margin-bottom:12px}}
  canvas{{max-height:210px}}

  /* Case cards */
  .card{{background:#fff;border-radius:12px;margin-bottom:16px;overflow:hidden;
         box-shadow:0 1px 4px rgba(0,0,0,.07)}}
  .card-header{{display:flex;align-items:center;gap:10px;padding:10px 16px;
                background:#f8fafc;border-bottom:1px solid #e2e8f0;flex-wrap:wrap}}
  .case-num{{font-weight:800;font-size:.8rem;color:#64748b}}
  .lang-tag{{font-size:.72rem;font-weight:700;padding:2px 8px;border-radius:999px}}
  .expected{{font-size:.8rem;color:#475569;flex:1}}

  .code-block{{background:#0f172a;padding:11px 16px;overflow-x:auto}}
  .code-block pre{{color:#e2e8f0;font-family:'JetBrains Mono','Fira Code',monospace;
                   font-size:.78rem;line-height:1.6;white-space:pre-wrap;word-break:break-word}}

  .versus{{display:flex;align-items:stretch;border-bottom:1px solid #f1f5f9}}
  .ver{{flex:1;padding:14px 16px}}
  .v1{{background:#fffbeb;border-right:1px solid #fde68a}}
  .v2{{background:#f0fdf4}}
  .ver-label{{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;
              color:#94a3b8;margin-bottom:8px}}
  .ver-row{{display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:.83rem;flex-wrap:wrap}}
  .field-lbl{{font-size:.67rem;font-weight:700;color:#94a3b8;width:36px;flex-shrink:0}}
  .sev-badge{{color:#fff;font-size:.72rem;font-weight:700;padding:2px 8px;border-radius:999px}}
  .elapsed{{font-size:.72rem;color:#94a3b8;margin-left:auto}}
  .ver-foot{{margin-top:8px}}
  .divider{{display:flex;align-items:center;justify-content:center;
            padding:0 10px;font-size:.8rem;font-weight:700;color:#94a3b8;
            background:#f8fafc;border-left:1px solid #e2e8f0;border-right:1px solid #e2e8f0}}
  .tick{{font-size:.78rem;font-weight:700;padding:2px 8px;border-radius:999px}}
  .tick.ok{{background:#dcfce7;color:#166534}}
  .tick.miss{{background:#fee2e2;color:#991b1b}}

  .fix-section{{padding:10px 16px 14px;background:#f8fafc}}
  .fix-label{{font-size:.67rem;font-weight:700;text-transform:uppercase;
              letter-spacing:.06em;color:#94a3b8;margin-bottom:4px}}
  .fix-block{{font-family:'JetBrains Mono','Fira Code',monospace;font-size:.78rem;
              color:#1e293b;background:#fff;border:1px solid #e2e8f0;padding:8px 10px;
              border-radius:6px;white-space:pre-wrap;word-break:break-word;line-height:1.6}}

  @media(max-width:640px){{
    .heroes,.charts{{flex-direction:column}}
    .versus{{flex-direction:column}}
    .divider{{padding:6px;border:none;border-top:1px solid #e2e8f0;border-bottom:1px solid #e2e8f0}}
    .v1{{border-right:none;border-bottom:1px solid #fde68a}}
  }}
</style>
</head>
<body>
<h1>Security Benchmark — V1 vs V2</h1>
<p class="sub">ScanOps · {now} · model: <code>{MODEL}</code> · 20 test cases</p>

<div class="heroes">
  <div class="hero" style="background:#dc2626;">
    <div class="hero-lbl">V1 Detection Rate</div>
    <div class="hero-val">{v1_pct}%</div>
    <div class="hero-sub">Basic prompt · {v1_det}/20</div>
  </div>
  <div class="hero" style="background:{det_color};">
    <div class="hero-lbl">V2 Detection Rate</div>
    <div class="hero-val">{v2_pct}%</div>
    <div class="hero-sub">OWASP/CWE prompt · {v2_det}/20</div>
  </div>
  <div class="hero" style="background:{delta_color};">
    <div class="hero-lbl">Detection Improvement</div>
    <div class="hero-val">{delta_p_str}</div>
    <div class="hero-sub">percentage points</div>
  </div>
  <div class="hero" style="background:#334155;">
    <div class="hero-lbl">Avg Response Time</div>
    <div class="hero-val">{v2_avg}s</div>
    <div class="hero-sub" style="color:{time_color};">V1: {v1_avg}s → {delta_t_str}</div>
  </div>
</div>

<p class="section-title">Detection by Language</p>
<div class="lang-table-wrap">
  <table>
    <thead><tr><th>Language</th><th class="center">V1</th><th class="center">V2</th><th class="center">Change</th></tr></thead>
    <tbody>{lang_rows}</tbody>
  </table>
</div>

<div class="charts">
  <div class="chart-box">
    <h2>Detections per Language — V1 vs V2</h2>
    <canvas id="chartDet"></canvas>
  </div>
  <div class="chart-box">
    <h2>Avg Response Time per Language (s) — V2</h2>
    <canvas id="chartTime"></canvas>
  </div>
</div>

<p class="section-title">Case-by-Case Comparison</p>
{cards}

<script>
const labels = {chart_labels};
const v1data  = {chart_v1};
const v2data  = {chart_v2};
const maxData = {chart_max};

const langColors = {json.dumps([LANG_COLOR.get(l, '#94a3b8') for l in langs])};

new Chart(document.getElementById('chartDet'), {{
  type: 'bar',
  data: {{
    labels,
    datasets: [
      {{ label: 'V1', data: v1data, backgroundColor: 'rgba(220,38,38,.65)',
         borderRadius: 4, borderSkipped: false }},
      {{ label: 'V2', data: v2data, backgroundColor: 'rgba(34,197,94,.75)',
         borderRadius: 4, borderSkipped: false }},
    ]
  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ position: 'top' }} }},
    scales: {{
      y: {{ beginAtZero: true, max: Math.max(...maxData),
            title: {{ display: true, text: 'detected' }} }},
      x: {{ grid: {{ display: false }} }}
    }}
  }}
}});

new Chart(document.getElementById('chartTime'), {{
  type: 'bar',
  data: {{
    labels,
    datasets: [{{
      label: 'Avg Time (s)',
      data: {chart_time_data},
      backgroundColor: langColors,
      borderRadius: 4, borderSkipped: false,
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      y: {{ beginAtZero: true, title: {{ display: true, text: 'seconds' }} }},
      x: {{ grid: {{ display: false }} }}
    }}
  }}
}});
</script>
</body>
</html>"""


def main():
    REPORTS.mkdir(exist_ok=True)
    v2_results = []

    print(f"모델: {MODEL}  |  V2 프롬프트 (OWASP/CWE)  |  케이스 {len(CASES)}개")
    print(f"{'─'*58}")

    for case in CASES:
        print(f"[{case['id']:02d}/20] [{case['language']}] {case['expected_vuln']}")
        response, elapsed = query_model(case["language"], case["code"])
        parsed  = parse_v2(response)
        ok      = is_detected(parsed.get("VULN_TYPE", ""), case["expected_vuln"])
        v1_ok   = V1_RESULTS[case["id"] - 1]["detected"]

        v2_results.append({**case, "response": response, "parsed": parsed,
                           "elapsed": elapsed, "detected": ok})

        tick  = "✓" if ok else "✗"
        arrow = "↑ IMPROVED" if ok and not v1_ok else ("↓ REGRESSED" if not ok and v1_ok else "= same")
        print(f"  {tick} {parsed.get('VULN_TYPE','?')[:50]}  [{parsed.get('SEVERITY','?')}]  {elapsed}s  {arrow}\n")

    v1_det = sum(1 for r in V1_RESULTS if r["detected"])
    v2_det = sum(1 for r in v2_results if r["detected"])
    v1_avg = round(sum(r["elapsed"] for r in V1_RESULTS) / len(V1_RESULTS), 2)
    v2_avg = round(sum(r["elapsed"] for r in v2_results) / len(v2_results), 2)

    html = build_html(v2_results)
    OUTPUT.write_text(html, encoding="utf-8")

    print(f"{'─'*58}")
    print(f"탐지율   V1: {v1_det}/20 ({round(v1_det/20*100,1)}%)  →  V2: {v2_det}/20 ({round(v2_det/20*100,1)}%)")
    print(f"응답시간 V1: {v1_avg}s  →  V2: {v2_avg}s")
    print(f"HTML 저장: {OUTPUT}")


if __name__ == "__main__":
    main()
