import json
import time
import urllib.request
from pathlib import Path
from datetime import datetime

API_URL  = "http://localhost:11434/api/generate"
MODEL    = "gemma:2b"
REPORTS  = Path(__file__).resolve().parent.parent / "reports"
OUTPUT   = REPORTS / "gemma_benchmark.html"
SUFFIX   = " Answer in 3 sentences maximum."

QUESTIONS = [
    "What is SQL injection and how does it work?",
    "Explain XSS (Cross-Site Scripting) attack",
    "What is CVE-2026-6747 and how severe is it?",
    "How does a buffer overflow attack work?",
    "What is CSRF attack? Give an example.",
    "Explain the difference between authentication and authorization vulnerabilities",
]

# 이전 실행 결과 (프롬프트 제약 없음)
PREV_RESULTS = [
    {"elapsed": 13.09, "words": 359},
    {"elapsed": 10.96, "words": 342},
    {"elapsed":  6.33, "words": 186},
    {"elapsed":  8.81, "words": 285},
    {"elapsed":  8.68, "words": 303},
    {"elapsed":  9.52, "words": 310},
]


def query(prompt: str) -> tuple[str, float, int]:
    payload = json.dumps({"model": MODEL, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(
        API_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = json.loads(resp.read())
    elapsed = time.perf_counter() - t0
    text = body["response"]
    return text, round(elapsed, 2), len(text.split())


def badge(elapsed: float) -> tuple[str, str]:
    if elapsed < 1.0:
        return "#22c55e", "< 1s"
    if elapsed < 3.0:
        return "#eab308", f"{elapsed:.2f}s"
    return "#ef4444", f"{elapsed:.2f}s"


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_html(new_results: list[dict]) -> str:
    now      = datetime.now().strftime("%Y-%m-%d %H:%M")
    labels   = json.dumps([f"Q{i+1}" for i in range(len(QUESTIONS))])
    old_times = json.dumps([r["elapsed"] for r in PREV_RESULTS])
    new_times = json.dumps([r["elapsed"] for r in new_results])
    avg_old  = round(sum(r["elapsed"] for r in PREV_RESULTS) / len(PREV_RESULTS), 2)
    avg_new  = round(sum(r["elapsed"] for r in new_results)  / len(new_results),  2)
    speedup  = round((avg_old - avg_new) / avg_old * 100, 1)

    cards = ""
    for i, (q, prev, curr) in enumerate(zip(QUESTIONS, PREV_RESULTS, new_results)):
        bc_p, bl_p = badge(prev["elapsed"])
        bc_c, bl_c = badge(curr["elapsed"])
        delta = round(prev["elapsed"] - curr["elapsed"], 2)
        delta_str = f"−{delta:.2f}s" if delta >= 0 else f"+{abs(delta):.2f}s"
        delta_color = "#22c55e" if delta >= 0 else "#ef4444"
        escaped_ans = esc(curr["answer"]).replace("\n", "<br>")
        cards += f"""
        <div class="card">
          <div class="question">Q{i+1}. {esc(q)}</div>
          <div class="compare-row">
            <div class="col-label old-label">No constraint</div>
            <div class="col-label new-label">3-sentence max</div>
          </div>
          <div class="compare-row meta-row">
            <div class="meta-cell">
              <span class="badge" style="background:{bc_p};">{bl_p}</span>
              <span class="words">{prev["words"]} words</span>
            </div>
            <div class="delta" style="color:{delta_color};">{delta_str}</div>
            <div class="meta-cell">
              <span class="badge" style="background:{bc_c};">{bl_c}</span>
              <span class="words">{curr["words"]} words</span>
            </div>
          </div>
          <div class="answer-label">Response (constrained)</div>
          <div class="answer">{escaped_ans}</div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gemma 2B Benchmark Comparison — ScanOps</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f4f8;color:#1e293b;padding:24px}}
  h1{{font-size:1.6rem;font-weight:700;margin-bottom:4px}}
  .sub{{color:#64748b;font-size:.9rem;margin-bottom:24px}}

  .summary{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px}}
  .stat{{background:#fff;border-radius:12px;padding:18px 24px;flex:1;min-width:140px;
         box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .stat-label{{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:#64748b}}
  .stat-value{{font-size:1.8rem;font-weight:700;margin-top:4px}}
  .blue{{color:#3b82f6}}.green{{color:#22c55e}}.purple{{color:#a855f7}}
  .orange{{color:#f97316}}.red{{color:#ef4444}}

  .chart-box{{background:#fff;border-radius:12px;padding:24px;margin-bottom:28px;
              box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .chart-box h2{{font-size:1rem;font-weight:600;margin-bottom:16px;color:#334155}}
  canvas{{max-height:260px}}

  .card{{background:#fff;border-radius:12px;margin-bottom:20px;overflow:hidden;
         box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .question{{background:#2563eb;color:#fff;padding:13px 20px;font-weight:600;font-size:.93rem;line-height:1.4}}

  .compare-row{{display:flex;align-items:center;gap:0}}
  .col-label{{flex:1;text-align:center;font-size:.72rem;font-weight:600;
              text-transform:uppercase;letter-spacing:.04em;padding:7px 12px}}
  .old-label{{background:#fef3c7;color:#92400e;border-right:1px solid #fde68a}}
  .new-label{{background:#dcfce7;color:#166534}}

  .meta-row{{padding:8px 16px;border-top:1px solid #f1f5f9;border-bottom:1px solid #f1f5f9;
             background:#fafafa;justify-content:space-between;align-items:center}}
  .meta-cell{{display:flex;align-items:center;gap:8px;flex:1}}
  .meta-cell:last-child{{justify-content:flex-end}}
  .delta{{font-size:.85rem;font-weight:700;padding:0 12px;white-space:nowrap}}
  .badge{{color:#fff;font-size:.76rem;font-weight:700;padding:3px 10px;border-radius:999px}}
  .words{{font-size:.76rem;color:#94a3b8}}

  .answer-label{{font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;
                 color:#64748b;padding:12px 20px 4px;background:#f8fafc}}
  .answer{{padding:12px 20px 18px;font-size:.88rem;line-height:1.7;color:#334155;
           white-space:pre-wrap;word-break:break-word;background:#f8fafc}}

  @media(max-width:600px){{
    .summary{{flex-direction:column}}
    .stat-value{{font-size:1.4rem}}
    .delta{{padding:0 6px;font-size:.78rem}}
  }}
</style>
</head>
<body>
<h1>Gemma 2B — Constraint Comparison</h1>
<p class="sub">ScanOps Model · {now} · Prompt suffix: <code>"{SUFFIX.strip()}"</code></p>

<div class="summary">
  <div class="stat">
    <div class="stat-label">Model</div>
    <div class="stat-value blue" style="font-size:1.1rem">{MODEL}</div>
  </div>
  <div class="stat">
    <div class="stat-label">Avg (no constraint)</div>
    <div class="stat-value red">{avg_old}s</div>
  </div>
  <div class="stat">
    <div class="stat-label">Avg (constrained)</div>
    <div class="stat-value green">{avg_new}s</div>
  </div>
  <div class="stat">
    <div class="stat-label">Speed-up</div>
    <div class="stat-value orange">{speedup}%</div>
  </div>
</div>

<div class="chart-box">
  <h2>Response Time Comparison per Question (seconds)</h2>
  <canvas id="chart"></canvas>
</div>

{cards}

<script>
new Chart(document.getElementById('chart'), {{
  type: 'bar',
  data: {{
    labels: {labels},
    datasets: [
      {{
        label: 'No constraint',
        data: {old_times},
        backgroundColor: 'rgba(239,68,68,0.7)',
        borderRadius: 4,
        borderSkipped: false,
      }},
      {{
        label: '3-sentence max',
        data: {new_times},
        backgroundColor: 'rgba(34,197,94,0.7)',
        borderRadius: 4,
        borderSkipped: false,
      }}
    ]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ position: 'top' }},
      tooltip: {{ callbacks: {{ label: ctx => ` ${{ctx.dataset.label}}: ${{ctx.parsed.y}}s` }} }}
    }},
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
    new_results = []

    print(f"모델: {MODEL}  |  제약: '{SUFFIX.strip()}'  |  질문 {len(QUESTIONS)}개")
    print(f"{'─'*55}")
    for i, q in enumerate(QUESTIONS, 1):
        prompt = q + SUFFIX
        print(f"[{i}/{len(QUESTIONS)}] {q[:55]}...")
        answer, elapsed, words = query(prompt)
        new_results.append({"question": q, "answer": answer, "elapsed": elapsed, "words": words})
        prev = PREV_RESULTS[i - 1]
        delta = round(prev["elapsed"] - elapsed, 2)
        sign  = "↓" if delta >= 0 else "↑"
        print(f"  이전: {prev['elapsed']:.2f}s ({prev['words']}w)  →  지금: {elapsed:.2f}s ({words}w)  {sign}{abs(delta):.2f}s\n")

    avg_old = round(sum(r["elapsed"] for r in PREV_RESULTS) / len(PREV_RESULTS), 2)
    avg_new = round(sum(r["elapsed"] for r in new_results)  / len(new_results),  2)
    speedup = round((avg_old - avg_new) / avg_old * 100, 1)

    html = build_html(new_results)
    OUTPUT.write_text(html, encoding="utf-8")

    print(f"{'─'*55}")
    print(f"평균 응답시간  이전: {avg_old}s  →  지금: {avg_new}s  ({speedup}% 단축)")
    print(f"HTML 저장: {OUTPUT}")


if __name__ == "__main__":
    main()
