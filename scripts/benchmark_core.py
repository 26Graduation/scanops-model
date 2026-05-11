"""
ScanOps Security Benchmark — 공통 프레임워크

친구들과 모델을 비교할 때 이 파일의 로직을 공유한다.
각자 어댑터(adapters/ 폴더)만 구현하면 동일한 20개 케이스로 공정하게 비교 가능.

사용법:
    from benchmark_core import run_benchmark
    from adapters.grok_adapter import query   # 또는 자신의 어댑터

    results = run_benchmark(query, model_name="My Model")
    # → reports/results_My_Model.json 저장
    # → reports/benchmark_My_Model.html 저장
"""

import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Callable

REPORTS = Path(__file__).resolve().parent.parent / "reports"

# ── 공통 20개 테스트 케이스 ────────────────────────────────────────────────────
# 이 케이스는 절대 수정하지 말 것 — 모든 모델이 동일한 문제를 풀어야 함

CASES = [
    # React / Next.js
    {"id":  1, "language": "React / Next.js",     "code": 'return <div dangerouslySetInnerHTML={{__html: userInput}} />;',                            "expected_vuln": "XSS"},
    {"id":  2, "language": "React / Next.js",     "code": 'return <a href={`javascript:${userAction}`}>Click</a>;',                                   "expected_vuln": "XSS (javascript: URI)"},
    {"id":  3, "language": "React / Next.js",     "code": "eval(searchParams.get('callback'));",                                                       "expected_vuln": "Code Injection via eval"},
    {"id":  4, "language": "React / Next.js",     "code": '<img src={user.avatar} onError={user.fallback} />',                                        "expected_vuln": "XSS via event handler"},
    # Node.js / Express
    {"id":  5, "language": "Node.js / Express",   "code": 'db.query("SELECT * FROM users WHERE id=" + req.params.id);',                              "expected_vuln": "SQL Injection"},
    {"id":  6, "language": "Node.js / Express",   "code": "exec(req.body.command);",                                                                   "expected_vuln": "Command Injection"},
    {"id":  7, "language": "Node.js / Express",   "code": "res.setHeader('Access-Control-Allow-Origin', '*');",                                       "expected_vuln": "Insecure CORS"},
    {"id":  8, "language": "Node.js / Express",   "code": "jwt.verify(token, 'hardcoded_secret_key');",                                               "expected_vuln": "Hardcoded Secret"},
    # Java Spring Boot
    {"id":  9, "language": "Java Spring Boot",    "code": 'String query = "SELECT * FROM " + tableName;\nstmt.execute(query);',                       "expected_vuln": "SQL Injection"},
    {"id": 10, "language": "Java Spring Boot",    "code": "Runtime.getRuntime().exec(userInput);",                                                     "expected_vuln": "Command Injection"},
    {"id": 11, "language": "Java Spring Boot",    "code": '@RequestMapping(value="/**")\npublic ResponseEntity<?> handle(HttpServletRequest req) {}',  "expected_vuln": "Overly Permissive Endpoint"},
    {"id": 12, "language": "Java Spring Boot",    "code": "if (password.equals(inputPassword)) { grantAccess(); }",                                   "expected_vuln": "Timing Attack"},
    # Python
    {"id": 13, "language": "Python",              "code": "import pickle\nobj = pickle.loads(user_data)",                                             "expected_vuln": "Insecure Deserialization"},
    {"id": 14, "language": "Python",              "code": "import subprocess\nsubprocess.call(user_input, shell=True)",                                "expected_vuln": "Command Injection"},
    {"id": 15, "language": "Python",              "code": "import yaml\ndata = yaml.load(user_input)  # not safe_load",                               "expected_vuln": "Arbitrary Code Execution via YAML"},
    {"id": 16, "language": "Python",              "code": 'import os\nos.system(f"ping {host}")',                                                     "expected_vuln": "Command Injection"},
    # C
    {"id": 17, "language": "C",                   "code": "printf(user_input);  // user-controlled format string",                                    "expected_vuln": "Format String Attack"},
    {"id": 18, "language": "C",                   "code": "char buf[64];\nstrcpy(buf, argv[1]);  // no bounds check",                                 "expected_vuln": "Buffer Overflow"},
    # GitHub Actions YAML
    {"id": 19, "language": "GitHub Actions YAML", "code": "- run: echo ${{ github.event.issue.title }}",                                              "expected_vuln": "Script Injection via untrusted input"},
    {"id": 20, "language": "GitHub Actions YAML", "code": "- uses: actions/checkout@main  # unpinned version",                                        "expected_vuln": "Supply Chain Attack (unpinned action)"},
]

# 프롬프트 — 모든 어댑터가 이 형식으로 응답을 유도해야 함
PROMPT_TMPL = """\
You are a security code reviewer.
Analyze this {language} code for security vulnerabilities.

Code:
{code}

Respond in this exact format:
VULNERABILITY: [vulnerability name with CWE ID if known]
SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]
ATTACK: [attack scenario in one sentence]
FIX: [fixed code only, no explanation]\
"""

# ── 파서 ───────────────────────────────────────────────────────────────────────

def parse_response(text: str) -> dict:
    """LLM 응답에서 구조화된 필드를 추출한다."""
    KEY_ALIASES = {
        "VULNERABILITY": r"(?:vulnerability|vuln)",
        "SEVERITY":      r"severity",
        "ATTACK":        r"attack",
        "FIX":           r"fix",
    }
    fields = {}
    for canonical, pattern in KEY_ALIASES.items():
        m = re.search(
            rf"^\*{{0,2}}{pattern}\*{{0,2}}:[ \t]*(.+)",
            text, re.MULTILINE | re.IGNORECASE,
        )
        fields[canonical] = m.group(1).strip().strip("*").strip() if m else "—"

    m_fix = re.search(r"^\*{0,2}fix\*{0,2}:[ \t]*([\s\S]+)", text, re.MULTILINE | re.IGNORECASE)
    if m_fix:
        raw = re.sub(r"^```[^\n]*\n", "", m_fix.group(1).strip()).rstrip("`").strip()
        fields["FIX"] = raw

    for k in ("VULNERABILITY", "SEVERITY", "ATTACK"):
        fields[k] = re.sub(r"\*+", "", fields[k]).strip()

    return fields


# 응답 표현이 달라도 같은 취약점을 인정하는 CWE 매핑
_CWE_ALIASES: dict[str, list[str]] = {
    "xss":                           ["cwe-79", "cwe-80", "cross-site scripting"],
    "sql injection":                 ["cwe-89"],
    "command injection":             ["cwe-78", "cwe-77"],
    "hardcoded secret":              ["cwe-798", "cwe-259", "hard-coded"],
    "insecure cors":                 ["cwe-942", "cwe-346"],
    "timing attack":                 ["cwe-208", "cwe-362"],
    "overly permissive":             ["cwe-284", "cwe-285", "cwe-807", "permissive"],
    "insecure deserialization":      ["cwe-502"],
    "arbitrary code execution via yaml": ["cwe-502", "yaml"],
    "supply chain":                  ["cwe-829", "unpinned"],
    "buffer overflow":               ["cwe-120", "cwe-121", "cwe-122"],
    "format string":                 ["cwe-134"],
    "script injection":              ["cwe-78", "cwe-77", "injection"],
    "code injection":                ["cwe-94", "cwe-95"],
}


def detected(parsed: dict, expected: str) -> bool:
    """모델 응답이 기대 취약점을 탐지했는지 판정한다."""
    vuln_lower = parsed.get("VULNERABILITY", "").lower()
    # 1차: 키워드 직접 매칭
    if any(w in vuln_lower for w in expected.lower().split()):
        return True
    # 2차: CWE 번호 / 별칭 매칭 (모델마다 표현이 달라도 인정)
    for key, aliases in _CWE_ALIASES.items():
        if any(k in expected.lower() for k in key.split()):
            if any(alias in vuln_lower for alias in aliases):
                return True
    return False


# ── 벤치마크 실행 ───────────────────────────────────────────────────────────────

QueryFn = Callable[[str, str], tuple[str, float]]
"""어댑터가 구현해야 하는 함수 시그니처: (language, code) → (response_text, elapsed_sec)"""


def run_benchmark(
    query_fn: QueryFn,
    model_name: str,
    save_json: bool = True,
    verbose: bool = True,
) -> list[dict]:
    """
    공통 20개 케이스를 query_fn으로 실행하고 결과를 반환한다.

    Args:
        query_fn:   어댑터 함수. (language, code) → (response, elapsed) 반환.
        model_name: 리포트에 표시될 모델 이름. 파일명에도 사용.
        save_json:  True면 reports/results_{model_name}.json 저장.
        verbose:    True면 케이스별 진행 상황 출력.

    Returns:
        결과 dict 리스트 (각 케이스에 response, parsed, elapsed, detected 포함)
    """
    REPORTS.mkdir(exist_ok=True)
    results = []
    safe_name = model_name.replace(" ", "_").replace("/", "-")

    if verbose:
        print(f"\n[{model_name}] 벤치마크 시작 — {len(CASES)}개 케이스")
        print("─" * 60)

    for case in CASES:
        if verbose:
            print(f"[{case['id']:02d}/20] [{case['language']}] {case['expected_vuln']}")

        try:
            prompt   = PROMPT_TMPL.format(language=case["language"], code=case["code"])
            response, elapsed = query_fn(case["language"], case["code"])
        except Exception as e:
            if verbose:
                print(f"  오류: {e}\n")
            results.append({**case, "response": "", "parsed": {}, "elapsed": 0.0,
                             "detected": False, "error": str(e)})
            continue

        parsed = parse_response(response)
        ok     = detected(parsed, case["expected_vuln"])
        results.append({**case, "response": response, "parsed": parsed,
                        "elapsed": elapsed, "detected": ok})

        if verbose:
            tick = "✓" if ok else "✗"
            sev  = parsed.get("SEVERITY", "?")
            print(f"  {tick} {parsed.get('VULNERABILITY','?')[:48]}  [{sev}]  {elapsed}s\n")

    # 요약
    total      = len(results)
    n_detected = sum(1 for r in results if r["detected"])
    valid      = [r for r in results if r["elapsed"] > 0]
    avg_t      = round(sum(r["elapsed"] for r in valid) / len(valid), 2) if valid else 0

    summary = {
        "model_name":  model_name,
        "timestamp":   datetime.now().isoformat(),
        "total":       total,
        "detected":    n_detected,
        "detect_pct":  round(n_detected / total * 100, 1),
        "avg_time":    avg_t,
        "results":     results,
    }

    if save_json:
        out = REPORTS / f"results_{safe_name}.json"
        out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        if verbose:
            print(f"JSON 저장: {out}")

    if verbose:
        print("─" * 60)
        print(f"탐지율: {n_detected}/{total} ({summary['detect_pct']}%)  평균응답: {avg_t}s")

    return summary


# ── HTML 단독 리포트 빌더 ────────────────────────────────────────────────────────

SEVERITY_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}
LANG_COLOR = {
    "React / Next.js": "#06b6d4", "Node.js / Express": "#22c55e",
    "Java Spring Boot": "#f97316", "Python": "#a855f7",
    "C": "#64748b", "GitHub Actions YAML": "#ec4899",
}


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_single_html(summary: dict) -> str:
    """단일 모델 결과를 HTML 리포트로 변환한다."""
    model_name = summary["model_name"]
    results    = summary["results"]
    now        = datetime.now().strftime("%Y-%m-%d %H:%M")
    total      = summary["total"]
    n_detected = summary["detected"]
    detect_pct = summary["detect_pct"]
    avg_all    = summary["avg_time"]

    lang_stats: dict[str, list] = {}
    for r in results:
        lang_stats.setdefault(r["language"], []).append(r)

    summary_cards = "".join(
        f"""<div class="stat" style="border-top:4px solid {LANG_COLOR.get(lang,'#94a3b8')};">
          <div class="stat-label">{esc(lang)}</div>
          <div class="stat-value" style="color:{LANG_COLOR.get(lang,'#94a3b8')};">
            {round(sum(r["elapsed"] for r in rows)/len(rows),2)}s</div>
          <div class="stat-sub">평균 · {sum(1 for r in rows if r["detected"])}/{len(rows)} 탐지</div>
        </div>"""
        for lang, rows in lang_stats.items()
    )

    sections = ""
    for lang, rows in lang_stats.items():
        color = LANG_COLOR.get(lang, "#94a3b8")
        cards = ""
        for r in rows:
            sev    = r["parsed"].get("SEVERITY", "").upper()
            sc     = SEVERITY_COLOR.get(sev, "#94a3b8")
            ok     = r["detected"]
            tc     = "#22c55e" if ok else "#ef4444"
            ec     = "#22c55e" if r["elapsed"] < 3 else ("#eab308" if r["elapsed"] < 8 else "#ef4444")
            cards += f"""
            <div class="case-card">
              <div class="case-header">
                <span class="case-num">#{r['id']}</span>
                <span class="expected">예상 취약점: {esc(r['expected_vuln'])}</span>
                <span class="tick" style="color:{tc};">{'✓ 탐지됨' if ok else '✗ 미탐지'}</span>
              </div>
              <div class="code-block"><pre>{esc(r['code'])}</pre></div>
              <div class="response-grid">
                <div class="resp-item"><span class="resp-label">취약점</span>
                  <span class="resp-value">{esc(r['parsed'].get('VULNERABILITY','—'))}</span></div>
                <div class="resp-item"><span class="resp-label">심각도</span>
                  <span class="sev-badge" style="background:{sc};">{sev or '—'}</span></div>
                <div class="resp-item full"><span class="resp-label">공격 시나리오</span>
                  <span class="resp-value">{esc(r['parsed'].get('ATTACK','—'))}</span></div>
                <div class="resp-item full"><span class="resp-label">수정 코드</span>
                  <pre class="fix-block">{esc(r['parsed'].get('FIX','—'))}</pre></div>
                <div class="resp-item"><span class="resp-label">응답시간</span>
                  <span class="resp-value" style="color:{ec};font-weight:700;">{r['elapsed']}s</span></div>
              </div>
            </div>"""
        sections += f'<section><div class="lang-header" style="background:{color};">{esc(lang)}</div>{cards}</section>'

    chart_labels = json.dumps(list(lang_stats.keys()))
    chart_times  = json.dumps([round(sum(r["elapsed"] for r in v)/len(v),2) for v in lang_stats.values()])
    chart_det    = json.dumps([round(sum(1 for r in v if r["detected"])/len(v)*100,1) for v in lang_stats.values()])
    chart_colors = json.dumps([LANG_COLOR.get(l,"#94a3b8") for l in lang_stats])

    return f"""<!DOCTYPE html><html lang="ko"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(model_name)} 벤치마크 — ScanOps</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f4f8;color:#1e293b;padding:24px}}
h1{{font-size:1.6rem;font-weight:700;margin-bottom:4px}}
.sub{{color:#64748b;font-size:.88rem;margin-bottom:24px}}
code{{font-family:monospace;font-size:.85em;background:#f1f5f9;padding:1px 5px;border-radius:4px}}
.top-stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
.hero{{background:#1e293b;color:#fff;border-radius:12px;padding:18px 28px;flex:1;min-width:140px}}
.hero-label{{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;opacity:.6}}
.hero-value{{font-size:2rem;font-weight:800;margin-top:2px}}
.lang-stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}}
.stat{{background:#fff;border-radius:12px;padding:14px 18px;flex:1;min-width:130px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
.stat-label{{font-size:.72rem;font-weight:600;color:#64748b;margin-bottom:4px}}
.stat-value{{font-size:1.5rem;font-weight:800}}
.stat-sub{{font-size:.72rem;color:#94a3b8;margin-top:2px}}
.charts{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px}}
.chart-box{{background:#fff;border-radius:12px;padding:20px;flex:1;min-width:260px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
.chart-box h2{{font-size:.9rem;font-weight:600;color:#334155;margin-bottom:14px}}
canvas{{max-height:200px}}
.lang-header{{color:#fff;font-weight:700;font-size:.9rem;padding:10px 18px;border-radius:10px 10px 0 0}}
section{{margin-bottom:28px}}
.case-card{{background:#fff;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.07)}}
.case-card+.case-card{{margin-top:1px}}
section .case-card:last-child{{border-radius:0 0 10px 10px}}
.case-header{{display:flex;align-items:center;gap:10px;padding:10px 16px;background:#f8fafc;border-bottom:1px solid #e2e8f0;flex-wrap:wrap}}
.case-num{{font-weight:800;font-size:.8rem;color:#64748b}}
.expected{{font-size:.78rem;color:#475569;flex:1}}
.tick{{font-size:.78rem;font-weight:700}}
.code-block{{background:#0f172a;padding:12px 16px}}
.code-block pre{{color:#e2e8f0;font-family:monospace;font-size:.8rem;line-height:1.6;white-space:pre-wrap;word-break:break-word}}
.response-grid{{display:grid;grid-template-columns:1fr 1fr}}
.resp-item{{padding:10px 16px;border-right:1px solid #f1f5f9;border-bottom:1px solid #f1f5f9}}
.resp-item.full{{grid-column:1/-1;border-right:none}}
.resp-label{{display:block;font-size:.67rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;margin-bottom:3px}}
.resp-value{{font-size:.83rem;color:#334155;line-height:1.5}}
.sev-badge{{display:inline-block;color:#fff;font-size:.75rem;font-weight:700;padding:2px 10px;border-radius:999px}}
.fix-block{{font-family:monospace;font-size:.78rem;color:#1e293b;background:#f0fdf4;padding:8px 10px;border-radius:6px;white-space:pre-wrap;word-break:break-word;line-height:1.6}}
</style></head><body>
<h1>{esc(model_name)} — 보안 코드 벤치마크</h1>
<p class="sub">ScanOps · {now} · 총 {total}개 케이스</p>
<div class="top-stats">
  <div class="hero"><div class="hero-label">총 케이스</div><div class="hero-value">{total}</div></div>
  <div class="hero" style="background:#166534;"><div class="hero-label">탐지</div><div class="hero-value">{n_detected}<span style="font-size:1rem;opacity:.8;"> / {total}</span></div></div>
  <div class="hero" style="background:#1d4ed8;"><div class="hero-label">탐지율</div><div class="hero-value">{detect_pct}%</div></div>
  <div class="hero" style="background:#7c3aed;"><div class="hero-label">평균 응답시간</div><div class="hero-value">{avg_all}s</div></div>
</div>
<div class="lang-stats">{summary_cards}</div>
<div class="charts">
  <div class="chart-box"><h2>언어별 평균 응답시간 (초)</h2><canvas id="ct"></canvas></div>
  <div class="chart-box"><h2>언어별 탐지율 (%)</h2><canvas id="cd"></canvas></div>
</div>
{sections}
<script>
const L={chart_labels},T={chart_times},D={chart_det},C={chart_colors};
new Chart(document.getElementById('ct'),{{type:'bar',data:{{labels:L,datasets:[{{label:'평균(초)',data:T,backgroundColor:C,borderRadius:5,borderSkipped:false}}]}},options:{{responsive:true,plugins:{{legend:{{display:false}}}},scales:{{y:{{beginAtZero:true}},x:{{grid:{{display:false}}}}}}}}}});
new Chart(document.getElementById('cd'),{{type:'bar',data:{{labels:L,datasets:[{{label:'탐지율%',data:D,backgroundColor:C,borderRadius:5,borderSkipped:false}}]}},options:{{responsive:true,plugins:{{legend:{{display:false}}}},scales:{{y:{{beginAtZero:true,max:100}},x:{{grid:{{display:false}}}}}}}}}});
</script>
</body></html>"""


def save_html(summary: dict) -> Path:
    """단일 모델 HTML 리포트를 저장하고 경로를 반환한다."""
    REPORTS.mkdir(exist_ok=True)
    safe_name = summary["model_name"].replace(" ", "_").replace("/", "-")
    out = REPORTS / f"benchmark_{safe_name}.html"
    out.write_text(build_single_html(summary), encoding="utf-8")
    return out
