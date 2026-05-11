"""
RAG Benchmark — ScanOps Step 6
benchmark_grok.py(Grok Only) vs RAG(ChromaDB + Grok) 비교.
동일한 20개 케이스, grok-3 고정.
"""

import json
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from grok_client import DEFAULT_MODEL
from rag_pipeline import analyze, _get_resources

REPORTS = Path(__file__).resolve().parent.parent / "reports"
OUTPUT  = REPORTS / "rag_benchmark.html"
MODEL   = "grok-3"

CASES = [
    {"id":  1, "language": "React / Next.js",      "code": 'return <div dangerouslySetInnerHTML={{__html: userInput}} />;',           "expected_vuln": "XSS"},
    {"id":  2, "language": "React / Next.js",      "code": 'return <a href={`javascript:${userAction}`}>Click</a>;',                  "expected_vuln": "XSS (javascript: URI)"},
    {"id":  3, "language": "React / Next.js",      "code": "eval(searchParams.get('callback'));",                                      "expected_vuln": "Code Injection via eval"},
    {"id":  4, "language": "React / Next.js",      "code": '<img src={user.avatar} onError={user.fallback} />',                       "expected_vuln": "XSS via event handler"},
    {"id":  5, "language": "Node.js / Express",    "code": 'db.query("SELECT * FROM users WHERE id=" + req.params.id);',              "expected_vuln": "SQL Injection"},
    {"id":  6, "language": "Node.js / Express",    "code": "exec(req.body.command);",                                                  "expected_vuln": "Command Injection"},
    {"id":  7, "language": "Node.js / Express",    "code": "res.setHeader('Access-Control-Allow-Origin', '*');",                      "expected_vuln": "Insecure CORS"},
    {"id":  8, "language": "Node.js / Express",    "code": "jwt.verify(token, 'hardcoded_secret_key');",                              "expected_vuln": "Hardcoded Secret"},
    {"id":  9, "language": "Java Spring Boot",     "code": 'String query = "SELECT * FROM " + tableName;\nstmt.execute(query);',      "expected_vuln": "SQL Injection"},
    {"id": 10, "language": "Java Spring Boot",     "code": "Runtime.getRuntime().exec(userInput);",                                   "expected_vuln": "Command Injection"},
    {"id": 11, "language": "Java Spring Boot",     "code": '@RequestMapping(value="/**")\npublic ResponseEntity<?> handle(HttpServletRequest req) { ... }', "expected_vuln": "Overly Permissive Endpoint"},
    {"id": 12, "language": "Java Spring Boot",     "code": "if (password.equals(inputPassword)) { grantAccess(); }",                  "expected_vuln": "Timing Attack"},
    {"id": 13, "language": "Python",               "code": "import pickle\nobj = pickle.loads(user_data)",                            "expected_vuln": "Insecure Deserialization"},
    {"id": 14, "language": "Python",               "code": "import subprocess\nsubprocess.call(user_input, shell=True)",              "expected_vuln": "Command Injection"},
    {"id": 15, "language": "Python",               "code": "import yaml\ndata = yaml.load(user_input)  # not safe_load",              "expected_vuln": "Arbitrary Code Execution via YAML"},
    {"id": 16, "language": "Python",               "code": 'import os\nos.system(f"ping {host}")',                                    "expected_vuln": "Command Injection"},
    {"id": 17, "language": "C",                    "code": "printf(user_input);  // user-controlled format string",                   "expected_vuln": "Format String Attack"},
    {"id": 18, "language": "C",                    "code": "char buf[64];\nstrcpy(buf, argv[1]);  // no bounds check",                "expected_vuln": "Buffer Overflow"},
    {"id": 19, "language": "GitHub Actions YAML",  "code": "- run: echo ${{ github.event.issue.title }}",                             "expected_vuln": "Script Injection via untrusted input"},
    {"id": 20, "language": "GitHub Actions YAML",  "code": "- uses: actions/checkout@main  # unpinned version",                       "expected_vuln": "Supply Chain Attack (unpinned action)"},
]

# grok-3 단독 결과 (benchmark_grok.py 실측값)
GROK_BASELINE = {
    "model":      "grok-3 (no RAG)",
    "detected":   17,
    "total":      20,
    "detect_pct": 85.0,
    "avg_time":   3.97,
}

SEVERITY_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}
LANG_COLOR = {
    "React / Next.js": "#06b6d4", "Node.js / Express": "#22c55e",
    "Java Spring Boot": "#f97316", "Python": "#a855f7",
    "C": "#64748b", "GitHub Actions YAML": "#ec4899",
}


def parse_response(text: str) -> dict:
    KEY_ALIASES = {
        "VULNERABILITY": r"(?:vulnerability|vuln)",
        "SEVERITY":      r"severity",
        "ATTACK":        r"attack",
        "FIX":           r"fix",
    }
    fields = {}
    for canonical, pattern in KEY_ALIASES.items():
        m = re.search(rf"^\*{{0,2}}{pattern}\*{{0,2}}:[ \t]*(.+)",
                      text, re.MULTILINE | re.IGNORECASE)
        fields[canonical] = m.group(1).strip().strip("*").strip() if m else "—"

    m_fix = re.search(r"^\*{0,2}fix\*{0,2}:[ \t]*([\s\S]+)", text, re.MULTILINE | re.IGNORECASE)
    if m_fix:
        raw = re.sub(r"^```[^\n]*\n", "", m_fix.group(1).strip()).rstrip("`").strip()
        fields["FIX"] = raw

    for k in ("VULNERABILITY", "SEVERITY", "ATTACK"):
        fields[k] = re.sub(r"\*+", "", fields[k]).strip()
    return fields


_CWE_ALIASES: dict[str, list[str]] = {
    "xss":                  ["cwe-79", "cwe-80"],
    "sql injection":        ["cwe-89"],
    "command injection":    ["cwe-78", "cwe-77"],
    "hardcoded secret":     ["cwe-798", "cwe-259", "hard-coded"],
    "insecure cors":        ["cwe-942", "cwe-346"],
    "timing attack":        ["cwe-208", "cwe-362"],
    "overly permissive":    ["cwe-284", "cwe-285", "cwe-807", "permissive"],
    "insecure deserialization": ["cwe-502"],
    "arbitrary code execution via yaml": ["cwe-502", "yaml"],
    "supply chain":         ["cwe-829", "unpinned"],
    "buffer overflow":      ["cwe-120", "cwe-121", "cwe-122"],
    "format string":        ["cwe-134"],
    "script injection":     ["cwe-78", "cwe-77", "injection"],
    "code injection":       ["cwe-94", "cwe-95"],
}


def detected(parsed: dict, expected: str) -> bool:
    vuln_lower = parsed.get("VULNERABILITY", "").lower()
    if any(w in vuln_lower for w in expected.lower().split()):
        return True
    for key, aliases in _CWE_ALIASES.items():
        if any(k in expected.lower() for k in key.split()):
            if any(alias in vuln_lower for alias in aliases):
                return True
    return False


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_html(results: list[dict]) -> str:
    now        = datetime.now().strftime("%Y-%m-%d %H:%M")
    total      = len(results)
    n_detected = sum(1 for r in results if r["detected"])
    detect_pct = round(n_detected / total * 100, 1)
    valid      = [r for r in results if r["elapsed"] > 0]
    avg_all    = round(sum(r["elapsed"] for r in valid) / len(valid), 2) if valid else 0

    det_delta  = detect_pct - GROK_BASELINE["detect_pct"]
    time_delta = avg_all - GROK_BASELINE["avg_time"]
    det_sign   = "+" if det_delta >= 0 else ""
    time_sign  = "+" if time_delta >= 0 else ""
    det_color  = "#22c55e" if det_delta >= 0 else "#ef4444"
    time_color = "#22c55e" if time_delta <= 0 else "#ef4444"

    lang_stats: dict[str, list] = {}
    for r in results:
        lang_stats.setdefault(r["language"], []).append(r)

    summary_cards = ""
    for lang, rows in lang_stats.items():
        avg_t = round(sum(r["elapsed"] for r in rows) / len(rows), 2)
        det   = sum(1 for r in rows if r["detected"])
        color = LANG_COLOR.get(lang, "#94a3b8")
        summary_cards += f"""
        <div class="stat" style="border-top:4px solid {color};">
          <div class="stat-label">{esc(lang)}</div>
          <div class="stat-value" style="color:{color};">{avg_t}s</div>
          <div class="stat-sub">avg · {det}/{len(rows)} detected</div>
        </div>"""

    sections = ""
    for lang, rows in lang_stats.items():
        color = LANG_COLOR.get(lang, "#94a3b8")
        cards = ""
        for r in rows:
            sev      = r["parsed"].get("SEVERITY", "").upper()
            sc       = SEVERITY_COLOR.get(sev, "#94a3b8")
            ok       = r["detected"]
            tick_c   = "#22c55e" if ok else "#ef4444"
            el_color = "#22c55e" if r["elapsed"] < 3 else ("#eab308" if r["elapsed"] < 8 else "#ef4444")

            cve_rows = ""
            for c in r.get("cves", []):
                sim_color = "#166534" if c["similarity"] > 0.8 else ("#92400e" if c["similarity"] > 0.6 else "#475569")
                cve_rows += f"""
                <tr>
                  <td>{esc(c['id'])}</td>
                  <td>{esc(c['cwe'])}</td>
                  <td>{esc(c['severity'])}</td>
                  <td style="color:{sim_color};font-weight:700;">{c['similarity']}</td>
                  <td>{esc(c['description'][:80])}…</td>
                </tr>"""

            cards += f"""
            <div class="case-card">
              <div class="case-header">
                <span class="case-num">#{r['id']}</span>
                <span class="expected">Expected: {esc(r['expected_vuln'])}</span>
                <span class="tick" style="color:{tick_c};">{'✓ Detected' if ok else '✗ Missed'}</span>
              </div>
              <div class="code-block"><pre>{esc(r['code'])}</pre></div>
              <details class="cve-details">
                <summary>Retrieved CVEs (top-5)</summary>
                <table class="cve-table">
                  <thead><tr><th>CVE</th><th>CWE</th><th>Severity</th><th>Sim</th><th>Description</th></tr></thead>
                  <tbody>{cve_rows}</tbody>
                </table>
              </details>
              <div class="response-grid">
                <div class="resp-item">
                  <span class="resp-label">VULNERABILITY</span>
                  <span class="resp-value">{esc(r['parsed'].get('VULNERABILITY','—'))}</span>
                </div>
                <div class="resp-item">
                  <span class="resp-label">SEVERITY</span>
                  <span class="sev-badge" style="background:{sc};">{sev or '—'}</span>
                </div>
                <div class="resp-item full">
                  <span class="resp-label">ATTACK</span>
                  <span class="resp-value">{esc(r['parsed'].get('ATTACK','—'))}</span>
                </div>
                <div class="resp-item full">
                  <span class="resp-label">FIX</span>
                  <pre class="fix-block">{esc(r['parsed'].get('FIX','—'))}</pre>
                </div>
                <div class="resp-item">
                  <span class="resp-label">Response Time</span>
                  <span class="resp-value" style="color:{el_color};font-weight:700;">{r['elapsed']}s</span>
                </div>
              </div>
            </div>"""

        sections += f"""
        <section>
          <div class="lang-header" style="background:{color};">{esc(lang)}</div>
          {cards}
        </section>"""

    chart_labels = json.dumps(list(lang_stats.keys()))
    chart_times  = json.dumps([round(sum(r["elapsed"] for r in rows)/len(rows), 2) for rows in lang_stats.values()])
    chart_colors = json.dumps([LANG_COLOR.get(l, "#94a3b8") for l in lang_stats])
    chart_det    = json.dumps([round(sum(1 for r in rows if r["detected"])/len(rows)*100, 1) for rows in lang_stats.values()])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RAG Benchmark — ScanOps</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f4f8;color:#1e293b;padding:24px}}
  h1{{font-size:1.6rem;font-weight:700;margin-bottom:4px}}
  .sub{{color:#64748b;font-size:.88rem;margin-bottom:24px}}
  code{{font-family:'JetBrains Mono','Fira Code',monospace;font-size:.85em;background:#f1f5f9;padding:1px 5px;border-radius:4px}}
  .rag-badge{{display:inline-block;background:#0891b2;color:#fff;font-size:.78rem;font-weight:700;padding:3px 12px;border-radius:999px;margin-left:8px;vertical-align:middle}}

  .top-stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px}}
  .hero{{background:#1e293b;color:#fff;border-radius:12px;padding:18px 28px;flex:1;min-width:140px}}
  .hero-label{{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;opacity:.6}}
  .hero-value{{font-size:2rem;font-weight:800;margin-top:2px}}

  .baseline-row{{background:#fff;border-radius:12px;padding:14px 20px;margin-bottom:20px;
                 box-shadow:0 1px 4px rgba(0,0,0,.08);display:flex;gap:24px;flex-wrap:wrap;align-items:center}}
  .bl-label{{font-size:.72rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.05em}}
  .bl-val{{font-size:.95rem;font-weight:700;color:#475569}}
  .bl-delta{{font-size:.9rem;font-weight:700}}

  .lang-stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}}
  .stat{{background:#fff;border-radius:12px;padding:14px 18px;flex:1;min-width:140px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .stat-label{{font-size:.72rem;font-weight:600;color:#64748b;margin-bottom:4px}}
  .stat-value{{font-size:1.5rem;font-weight:800}}
  .stat-sub{{font-size:.72rem;color:#94a3b8;margin-top:2px}}

  .charts{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px}}
  .chart-box{{background:#fff;border-radius:12px;padding:20px;flex:1;min-width:260px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .chart-box h2{{font-size:.9rem;font-weight:600;color:#334155;margin-bottom:14px}}
  canvas{{max-height:200px}}

  .lang-header{{color:#fff;font-weight:700;font-size:.9rem;padding:10px 18px;border-radius:10px 10px 0 0}}
  section{{margin-bottom:28px}}

  .case-card{{background:#fff;border-radius:0 0 10px 10px;margin-bottom:2px;box-shadow:0 1px 4px rgba(0,0,0,.07);overflow:hidden}}
  .case-card+.case-card{{border-radius:0;margin-top:1px}}
  section .case-card:last-child{{border-radius:0 0 10px 10px}}
  .case-header{{display:flex;align-items:center;gap:10px;padding:10px 16px;background:#f8fafc;border-bottom:1px solid #e2e8f0;flex-wrap:wrap}}
  .case-num{{font-weight:800;font-size:.8rem;color:#64748b}}
  .expected{{font-size:.78rem;color:#475569;flex:1}}
  .tick{{font-size:.78rem;font-weight:700}}

  .code-block{{background:#0f172a;padding:12px 16px;overflow-x:auto}}
  .code-block pre{{color:#e2e8f0;font-family:'JetBrains Mono','Fira Code',monospace;font-size:.8rem;line-height:1.6;white-space:pre-wrap;word-break:break-word}}

  .cve-details{{background:#f0f9ff;border-bottom:1px solid #bae6fd}}
  .cve-details summary{{padding:8px 16px;font-size:.78rem;font-weight:600;color:#0369a1;cursor:pointer}}
  .cve-table{{width:100%;border-collapse:collapse;font-size:.75rem}}
  .cve-table th{{background:#e0f2fe;padding:5px 10px;text-align:left;font-weight:700;color:#0369a1}}
  .cve-table td{{padding:5px 10px;border-bottom:1px solid #e0f2fe;color:#334155;vertical-align:top}}
  .cve-table tr:last-child td{{border-bottom:none}}

  .response-grid{{display:grid;grid-template-columns:1fr 1fr;gap:0}}
  .resp-item{{padding:10px 16px;border-right:1px solid #f1f5f9;border-bottom:1px solid #f1f5f9}}
  .resp-item.full{{grid-column:1/-1;border-right:none}}
  .resp-label{{display:block;font-size:.67rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;margin-bottom:3px}}
  .resp-value{{font-size:.83rem;color:#334155;line-height:1.5}}
  .sev-badge{{display:inline-block;color:#fff;font-size:.75rem;font-weight:700;padding:2px 10px;border-radius:999px}}
  .fix-block{{font-family:'JetBrains Mono','Fira Code',monospace;font-size:.78rem;color:#1e293b;background:#f0fdf4;padding:8px 10px;border-radius:6px;white-space:pre-wrap;word-break:break-word;line-height:1.6}}

  @media(max-width:640px){{
    .top-stats,.lang-stats,.charts{{flex-direction:column}}
    .response-grid{{grid-template-columns:1fr}}
    .resp-item.full{{grid-column:1}}
  }}
</style>
</head>
<body>
<h1>RAG Pipeline — Security Benchmark <span class="rag-badge">ChromaDB + Grok API</span></h1>
<p class="sub">ScanOps Model · {now} · {total} test cases · model: <code>{MODEL}</code> · CVE top-5 context</p>

<div class="top-stats">
  <div class="hero"><div class="hero-label">Total Cases</div><div class="hero-value">{total}</div></div>
  <div class="hero" style="background:#166534;"><div class="hero-label">Detected</div><div class="hero-value">{n_detected} <span style="font-size:1rem;opacity:.8;">/ {total}</span></div></div>
  <div class="hero" style="background:#1d4ed8;"><div class="hero-label">Detection Rate</div><div class="hero-value">{detect_pct}%</div></div>
  <div class="hero" style="background:#0891b2;"><div class="hero-label">Avg Response</div><div class="hero-value">{avg_all}s</div></div>
</div>

<div class="baseline-row">
  <div><div class="bl-label">Baseline (grok-3 no RAG)</div><div class="bl-val">{GROK_BASELINE['detect_pct']}% detection · {GROK_BASELINE['avg_time']}s avg</div></div>
  <div><div class="bl-label">Detection Rate Δ</div><div class="bl-delta" style="color:{det_color};">{det_sign}{det_delta:.1f}%p</div></div>
  <div><div class="bl-label">Response Time Δ</div><div class="bl-delta" style="color:{time_color};">{time_sign}{time_delta:.2f}s</div></div>
</div>

<div class="lang-stats">{summary_cards}</div>

<div class="charts">
  <div class="chart-box"><h2>Avg Response Time by Language (s)</h2><canvas id="chartTime"></canvas></div>
  <div class="chart-box"><h2>Detection Rate by Language (%)</h2><canvas id="chartDet"></canvas></div>
</div>

{sections}

<script>
const labels={chart_labels},timeData={chart_times},detData={chart_det},colors={chart_colors};
new Chart(document.getElementById('chartTime'),{{type:'bar',data:{{labels,datasets:[{{label:'Avg Time(s)',data:timeData,backgroundColor:colors,borderRadius:5,borderSkipped:false}}]}},options:{{responsive:true,plugins:{{legend:{{display:false}}}},scales:{{y:{{beginAtZero:true}},x:{{grid:{{display:false}}}}}}}}}});
new Chart(document.getElementById('chartDet'),{{type:'bar',data:{{labels,datasets:[{{label:'Detection %',data:detData,backgroundColor:colors,borderRadius:5,borderSkipped:false}}]}},options:{{responsive:true,plugins:{{legend:{{display:false}}}},scales:{{y:{{beginAtZero:true,max:100}},x:{{grid:{{display:false}}}}}}}}}});
</script>
</body>
</html>"""


def main():
    REPORTS.mkdir(exist_ok=True)
    results = []

    col, _ = _get_resources()
    print(f"[RAG Benchmark] 모델: {MODEL}  |  CVE 컬렉션: {col.count()}개  |  케이스: {len(CASES)}개")
    print("─" * 60)

    for case in CASES:
        print(f"[{case['id']:02d}/20] [{case['language']}] {case['expected_vuln']}")
        try:
            response, elapsed, cves = analyze(case["language"], case["code"], model=MODEL)
        except Exception as e:
            print(f"  오류: {e}\n")
            results.append({**case, "response": "", "parsed": {}, "elapsed": 0.0, "detected": False, "cves": []})
            continue

        parsed = parse_response(response)
        ok     = detected(parsed, case["expected_vuln"])
        results.append({**case, "response": response, "parsed": parsed,
                        "elapsed": elapsed, "detected": ok, "cves": cves})

        tick = "✓" if ok else "✗"
        top_cve = cves[0]["id"] if cves else "—"
        print(f"  {tick} {parsed.get('VULNERABILITY','?')[:45]}  [{parsed.get('SEVERITY','?')}]  {elapsed}s")
        print(f"    top CVE: {top_cve} (sim={cves[0]['similarity'] if cves else '—'})\n")

    valid      = [r for r in results if r["elapsed"] > 0]
    n_detected = sum(1 for r in results if r["detected"])
    total      = len(results)
    avg_t      = round(sum(r["elapsed"] for r in valid) / len(valid), 2) if valid else 0

    html = build_html(results)
    OUTPUT.write_text(html, encoding="utf-8")

    print("─" * 60)
    print(f"[RAG] 탐지율: {n_detected}/{total} ({round(n_detected/total*100,1)}%)")
    print(f"[RAG] 평균 응답시간: {avg_t}s")
    print(f"[RAG] grok-3 단독 대비: {GROK_BASELINE['detect_pct']}% → {round(n_detected/total*100,1)}%")
    print(f"HTML 저장: {OUTPUT}")


if __name__ == "__main__":
    main()
