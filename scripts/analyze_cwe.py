from collections import Counter
from pathlib import Path
import json
import chromadb

CHROMA_DIR  = Path(__file__).resolve().parent.parent / "chroma_db"
REPORTS     = Path(__file__).resolve().parent.parent / "reports"
OUTPUT      = REPORTS / "cwe_analysis.html"
COLLECTION  = "cve_collection"
TOP_N       = 10


def load_all(collection) -> list[dict]:
    total = collection.count()
    result = collection.get(limit=total, include=["metadatas", "documents"])
    rows = []
    for meta, doc in zip(result["metadatas"], result["documents"]):
        rows.append({**meta, "description": doc})
    return rows


def main():
    client     = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = client.get_collection(COLLECTION)
    rows       = load_all(collection)
    total      = len(rows)

    # ── CWE 집계 ──────────────────────────────────────────────────
    cwe_counter = Counter()
    for r in rows:
        cwe = (r.get("cwe_primary") or "").strip()
        cwe_counter[cwe or "Unknown"] += 1

    top10 = cwe_counter.most_common(TOP_N)

    # ── Severity 분포 ──────────────────────────────────────────────
    sev_counter = Counter()
    for r in rows:
        sev = (r.get("severity") or "").strip().upper() or "UNKNOWN"
        sev_counter[sev] += 1
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    sev_dist  = {k: sev_counter.get(k, 0) for k in sev_order if sev_counter.get(k, 0) > 0}

    # ── Score 통계 ─────────────────────────────────────────────────
    scores = [float(r.get("score") or 0) for r in rows if r.get("score")]
    score_avg = round(sum(scores) / len(scores), 2) if scores else 0
    score_max = round(max(scores), 2) if scores else 0
    score_min = round(min(scores), 2) if scores else 0

    # ── 터미널 출력 ────────────────────────────────────────────────
    print(f"\n{'═'*52}")
    print(f"  ChromaDB CWE 분포 분석  |  전체 {total}개 CVE")
    print(f"{'═'*52}")

    print(f"\n▶ Top {TOP_N} CWE (cwe_primary 기준)")
    print(f"  {'CWE':<20} {'Count':>6}  {'비율':>6}")
    print(f"  {'─'*36}")
    for cwe, cnt in top10:
        bar  = "█" * int(cnt / total * 40)
        pct  = round(cnt / total * 100, 1)
        print(f"  {cwe:<20} {cnt:>6}  {pct:>5.1f}%  {bar}")

    print(f"\n▶ Severity 분포")
    print(f"  {'Severity':<10} {'Count':>6}  {'비율':>6}")
    print(f"  {'─'*30}")
    for sev, cnt in sev_dist.items():
        pct = round(cnt / total * 100, 1)
        print(f"  {sev:<10} {cnt:>6}  {pct:>5.1f}%")

    print(f"\n▶ CVSS Score 통계")
    print(f"  평균: {score_avg}  최대: {score_max}  최소: {score_min}")
    print(f"{'═'*52}\n")

    # ── HTML 생성 ──────────────────────────────────────────────────
    REPORTS.mkdir(exist_ok=True)
    html = build_html(total, top10, sev_dist, score_avg, score_max, score_min, rows)
    OUTPUT.write_text(html, encoding="utf-8")
    print(f"HTML 저장: {OUTPUT}")


def build_html(total, top10, sev_dist, score_avg, score_max, score_min, rows):
    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # chart data
    cwe_labels  = json.dumps([c for c, _ in top10])
    cwe_counts  = json.dumps([n for _, n in top10])
    sev_labels  = json.dumps(list(sev_dist.keys()))
    sev_counts  = json.dumps(list(sev_dist.values()))

    SEV_COLORS = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c",
        "MEDIUM":   "#ca8a04", "LOW":  "#16a34a", "UNKNOWN": "#94a3b8",
    }
    sev_colors = json.dumps([SEV_COLORS.get(k, "#94a3b8") for k in sev_dist])

    # 상위 CWE별 severity 스택 데이터
    top_cwes   = [c for c, _ in top10]
    sev_keys   = list(sev_dist.keys())
    stack_data = {}
    for sev in sev_keys:
        stack_data[sev] = []
        for cwe in top_cwes:
            cnt = sum(
                1 for r in rows
                if (r.get("cwe_primary") or "Unknown") == cwe
                and (r.get("severity") or "UNKNOWN").upper() == sev
            )
            stack_data[sev].append(cnt)

    stack_datasets = []
    for sev in sev_keys:
        stack_datasets.append({
            "label": sev,
            "data":  stack_data[sev],
            "backgroundColor": SEV_COLORS.get(sev, "#94a3b8"),
            "borderRadius": 3,
            "borderSkipped": False,
        })

    # score 히스토그램 (0.5 단위 버킷)
    buckets = [f"{i/2:.1f}–{(i+1)/2:.1f}" for i in range(0, 20)]
    bucket_counts = [0] * 20
    for r in rows:
        s = float(r.get("score") or 0)
        idx = min(int(s * 2), 19)
        bucket_counts[idx] += 1

    # 샘플 테이블 (score 상위 10)
    top_cves = sorted(rows, key=lambda r: float(r.get("score") or 0), reverse=True)[:10]

    def esc(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    table_rows = ""
    for r in top_cves:
        sc = SEV_COLORS.get((r.get("severity") or "").upper(), "#94a3b8")
        desc = esc((r.get("description") or "")[:90])
        table_rows += f"""
        <tr>
          <td><code>{esc(r.get('id','?'))}</code></td>
          <td><span class="sev-badge" style="background:{sc};">{esc(r.get('severity','?'))}</span></td>
          <td class="score">{r.get('score','?')}</td>
          <td>{esc(r.get('cwe_primary','?'))}</td>
          <td class="desc">{desc}…</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CWE Distribution Analysis — ScanOps</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f4f8;color:#1e293b;padding:24px}}
  h1{{font-size:1.55rem;font-weight:800;margin-bottom:4px}}
  .sub{{color:#64748b;font-size:.85rem;margin-bottom:24px}}
  code{{font-family:'JetBrains Mono','Fira Code',monospace;font-size:.82em;
        background:#f1f5f9;padding:1px 6px;border-radius:4px}}

  .heroes{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
  .hero{{border-radius:12px;padding:18px 24px;flex:1;min-width:130px;color:#fff}}
  .hero-lbl{{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;opacity:.75}}
  .hero-val{{font-size:2rem;font-weight:800;margin-top:2px}}
  .hero-sub{{font-size:.72rem;opacity:.65;margin-top:2px}}

  .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}}
  .grid3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:24px}}
  .chart-box{{background:#fff;border-radius:12px;padding:20px;
              box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .chart-box h2{{font-size:.88rem;font-weight:700;color:#334155;margin-bottom:14px}}
  .chart-box.wide{{grid-column:1/-1}}
  canvas{{max-height:240px}}

  .section-title{{font-size:.82rem;font-weight:700;color:#475569;
                  text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px}}
  .table-wrap{{background:#fff;border-radius:12px;overflow:hidden;
               box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:24px;overflow-x:auto}}
  table{{width:100%;border-collapse:collapse;font-size:.83rem}}
  th{{background:#f8fafc;padding:9px 14px;text-align:left;font-size:.7rem;font-weight:700;
      text-transform:uppercase;letter-spacing:.05em;color:#64748b;border-bottom:1px solid #e2e8f0}}
  td{{padding:10px 14px;border-bottom:1px solid #f1f5f9;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  .score{{font-weight:700;color:#1e293b}}
  .desc{{color:#64748b;font-size:.8rem;max-width:300px}}
  .sev-badge{{color:#fff;font-size:.72rem;font-weight:700;padding:2px 8px;border-radius:999px;white-space:nowrap}}

  @media(max-width:700px){{
    .grid2,.grid3{{grid-template-columns:1fr}}
    .chart-box.wide{{grid-column:auto}}
  }}
</style>
</head>
<body>
<h1>CWE Distribution Analysis</h1>
<p class="sub">ScanOps ChromaDB · {now} · <code>cve_collection</code> · 전체 {total}개 CVE</p>

<div class="heroes">
  <div class="hero" style="background:#1e293b;">
    <div class="hero-lbl">Total CVEs</div>
    <div class="hero-val">{total}</div>
  </div>
  <div class="hero" style="background:#dc2626;">
    <div class="hero-lbl">Avg CVSS Score</div>
    <div class="hero-val">{score_avg}</div>
    <div class="hero-sub">max {score_max} · min {score_min}</div>
  </div>
  <div class="hero" style="background:#2563eb;">
    <div class="hero-lbl">Unique CWEs</div>
    <div class="hero-val">{len(set((r.get('cwe_primary') or 'Unknown') for r in rows))}</div>
  </div>
  <div class="hero" style="background:#7c3aed;">
    <div class="hero-lbl">CRITICAL + HIGH</div>
    <div class="hero-val">{sev_dist.get('CRITICAL',0) + sev_dist.get('HIGH',0)}</div>
    <div class="hero-sub">{round((sev_dist.get('CRITICAL',0)+sev_dist.get('HIGH',0))/total*100,1)}% of total</div>
  </div>
</div>

<div class="grid2">
  <div class="chart-box">
    <h2>Top {TOP_N} CWE — 건수 (Bar)</h2>
    <canvas id="cweBar"></canvas>
  </div>
  <div class="chart-box">
    <h2>Severity 분포 (Doughnut)</h2>
    <canvas id="sevDoughnut"></canvas>
  </div>
  <div class="chart-box wide">
    <h2>Top {TOP_N} CWE × Severity 스택 분포</h2>
    <canvas id="cweStack"></canvas>
  </div>
  <div class="chart-box wide">
    <h2>CVSS Score 히스토그램 (0.5 단위)</h2>
    <canvas id="scoreHist"></canvas>
  </div>
</div>

<p class="section-title">CVSS Score 상위 10개 CVE</p>
<div class="table-wrap">
  <table>
    <thead><tr><th>CVE ID</th><th>Severity</th><th>Score</th><th>CWE</th><th>Description</th></tr></thead>
    <tbody>{table_rows}</tbody>
  </table>
</div>

<script>
const cweLabels  = {cwe_labels};
const cweCounts  = {cwe_counts};
const sevLabels  = {sev_labels};
const sevCounts  = {sev_counts};
const sevColors  = {sev_colors};
const stackDS    = {json.dumps(stack_datasets)};
const histLabels = {json.dumps(buckets)};
const histData   = {json.dumps(bucket_counts)};

// 1. CWE Bar
new Chart(document.getElementById('cweBar'), {{
  type: 'bar',
  data: {{ labels: cweLabels,
    datasets: [{{ label: 'CVE 수', data: cweCounts,
      backgroundColor: 'rgba(37,99,235,.75)', borderRadius: 5, borderSkipped: false }}] }},
  options: {{ indexAxis: 'y', responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{ x: {{ beginAtZero: true }}, y: {{ grid: {{ display: false }} }} }} }}
}});

// 2. Severity Doughnut
new Chart(document.getElementById('sevDoughnut'), {{
  type: 'doughnut',
  data: {{ labels: sevLabels, datasets: [{{ data: sevCounts,
    backgroundColor: sevColors, borderWidth: 2, borderColor: '#fff' }}] }},
  options: {{ responsive: true, cutout: '60%',
    plugins: {{ legend: {{ position: 'right' }},
      tooltip: {{ callbacks: {{ label: ctx =>
        ` ${{ctx.label}}: ${{ctx.parsed}} (${{(ctx.parsed/sevCounts.reduce((a,b)=>a+b,0)*100).toFixed(1)}}%)` }} }} }} }}
}});

// 3. Stacked Bar
new Chart(document.getElementById('cweStack'), {{
  type: 'bar',
  data: {{ labels: cweLabels, datasets: stackDS }},
  options: {{ responsive: true, scales: {{
    x: {{ stacked: true, grid: {{ display: false }} }},
    y: {{ stacked: true, beginAtZero: true }} }},
    plugins: {{ legend: {{ position: 'top' }} }} }}
}});

// 4. Score Histogram
new Chart(document.getElementById('scoreHist'), {{
  type: 'bar',
  data: {{ labels: histLabels,
    datasets: [{{ label: 'CVE 수', data: histData,
      backgroundColor: histData.map((_, i) =>
        i>=18?'#dc2626': i>=14?'#ea580c': i>=10?'#ca8a04':'#22c55e'),
      borderRadius: 3, borderSkipped: false }}] }},
  options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }},
    scales: {{ x: {{ grid: {{ display: false }} }}, y: {{ beginAtZero: true }} }} }}
}});
</script>
</body>
</html>"""


if __name__ == "__main__":
    main()
