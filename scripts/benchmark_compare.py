"""
ScanOps 멀티모델 비교 벤치마크

여러 모델의 results_*.json을 로드해서 나란히 비교하는 HTML 리포트를 생성한다.

사용법:
    # 1. 각자 자신의 어댑터로 결과 JSON 생성
    python scripts/adapters/grok_adapter.py
    python scripts/adapters/ollama_adapter.py --model llama3:8b
    python scripts/adapters/openai_adapter.py --model gpt-4o

    # 2. 비교 리포트 생성 (reports/ 안의 results_*.json 전부 읽음)
    python scripts/benchmark_compare.py

    # 3. 특정 파일만 비교
    python scripts/benchmark_compare.py results_ScanOps_Grok.json results_GPT4o.json
"""

import json
import sys
from datetime import datetime
from pathlib import Path

REPORTS = Path(__file__).resolve().parent.parent / "reports"
OUTPUT  = REPORTS / "compare_report.html"

LANG_COLOR = {
    "React / Next.js": "#06b6d4", "Node.js / Express": "#22c55e",
    "Java Spring Boot": "#f97316", "Python": "#a855f7",
    "C": "#64748b", "GitHub Actions YAML": "#ec4899",
}
SEVERITY_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}


def esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def load_summaries(files: list[Path]) -> list[dict]:
    summaries = []
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        summaries.append(data)
        print(f"  로드: {f.name}  ({data['model_name']}  {data['detect_pct']}%  {data['avg_time']}s)")
    return sorted(summaries, key=lambda s: -s["detect_pct"])


def build_compare_html(summaries: list[dict]) -> str:
    now     = datetime.now().strftime("%Y-%m-%d %H:%M")
    n_cases = summaries[0]["total"] if summaries else 0
    models  = [s["model_name"] for s in summaries]

    # ── 상단 요약 카드 ────────────────────────────────────────────
    hero_cards = ""
    colors = ["#1e293b", "#1d4ed8", "#166534", "#7c3aed",
              "#0891b2", "#b45309", "#9f1239", "#065f46"]
    for i, s in enumerate(summaries):
        c = colors[i % len(colors)]
        hero_cards += f"""
        <div class="hero" style="background:{c};">
          <div class="hero-rank">#{i+1}</div>
          <div class="hero-name">{esc(s['model_name'])}</div>
          <div class="hero-pct">{s['detect_pct']}%</div>
          <div class="hero-sub">{s['detected']}/{s['total']} 탐지 · {s['avg_time']}s</div>
        </div>"""

    # ── 언어별 탐지율 차트 데이터 ─────────────────────────────────
    all_langs = list(LANG_COLOR.keys())
    chart_datasets = []
    palette = ["#3b82f6","#22c55e","#f97316","#a855f7","#06b6d4","#ec4899","#eab308","#64748b"]
    for i, s in enumerate(summaries):
        lang_map = {}
        for r in s["results"]:
            lang_map.setdefault(r["language"], []).append(r)
        det_pcts = [
            round(sum(1 for r in lang_map.get(l, []) if r["detected"])
                  / max(len(lang_map.get(l, [1])), 1) * 100, 1)
            for l in all_langs
        ]
        chart_datasets.append({
            "label":           s["model_name"],
            "data":            det_pcts,
            "backgroundColor": palette[i % len(palette)],
            "borderRadius":    4,
            "borderSkipped":   False,
        })

    # ── 케이스별 비교 테이블 ──────────────────────────────────────
    # 케이스 ID → 각 모델 결과 매핑
    case_map: dict[int, dict] = {}
    for s in summaries:
        for r in s["results"]:
            case_map.setdefault(r["id"], {"case": r})
            case_map[r["id"]][s["model_name"]] = r

    case_rows = ""
    for cid in sorted(case_map.keys()):
        entry = case_map[cid]
        case  = entry["case"]
        lang  = case["language"]
        lc    = LANG_COLOR.get(lang, "#94a3b8")

        cells = f"""<td class="case-id">#{cid}</td>
          <td><span class="lang-badge" style="background:{lc};">{esc(lang)}</span></td>
          <td class="expected">{esc(case['expected_vuln'])}</td>"""

        for s in summaries:
            r  = entry.get(s["model_name"], {})
            ok = r.get("detected", False)
            vuln = r.get("parsed", {}).get("VULNERABILITY", "—") if r else "—"
            sev  = r.get("parsed", {}).get("SEVERITY", "")
            sc   = SEVERITY_COLOR.get(sev.upper(), "#94a3b8")
            tc   = "#22c55e" if ok else "#ef4444"
            elapsed = r.get("elapsed", 0)
            cells += f"""
          <td class="model-cell">
            <span class="tick" style="color:{tc};">{'✓' if ok else '✗'}</span>
            <span class="vuln-text">{esc(vuln[:40])}</span>
            <span class="sev-mini" style="background:{sc};">{sev or '—'}</span>
            <span class="elapsed">{elapsed}s</span>
          </td>"""

        row_class = "row-miss" if any(
            not entry.get(s["model_name"], {}).get("detected", False) for s in summaries
        ) else "row-all"
        case_rows += f'<tr class="{row_class}">{cells}</tr>'

    # 테이블 헤더
    model_headers = "".join(f'<th class="model-th">{esc(m)}</th>' for m in models)

    chart_datasets_json = json.dumps(chart_datasets, ensure_ascii=False)
    lang_labels_json    = json.dumps(all_langs)
    models_json         = json.dumps(models)
    det_pcts_json       = json.dumps([s["detect_pct"] for s in summaries])
    avg_times_json      = json.dumps([s["avg_time"] for s in summaries])
    palette_json        = json.dumps(palette[:len(summaries)])

    return f"""<!DOCTYPE html><html lang="ko"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>모델 비교 벤치마크 — ScanOps</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f4f8;color:#1e293b;padding:24px}}
h1{{font-size:1.6rem;font-weight:700;margin-bottom:4px}}
h2{{font-size:1.1rem;font-weight:700;margin:28px 0 14px;color:#334155}}
.sub{{color:#64748b;font-size:.88rem;margin-bottom:28px}}

/* 순위 카드 */
.heroes{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:28px}}
.hero{{border-radius:14px;padding:20px 24px;flex:1;min-width:160px;color:#fff}}
.hero-rank{{font-size:.75rem;opacity:.7;font-weight:700;text-transform:uppercase;letter-spacing:.05em}}
.hero-name{{font-size:.88rem;font-weight:700;margin:4px 0 8px;line-height:1.3}}
.hero-pct{{font-size:2.2rem;font-weight:900}}
.hero-sub{{font-size:.75rem;opacity:.75;margin-top:4px}}

/* 차트 */
.charts{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px}}
.chart-box{{background:#fff;border-radius:12px;padding:20px;flex:1;min-width:280px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
.chart-box h3{{font-size:.9rem;font-weight:600;color:#334155;margin-bottom:14px}}
canvas{{max-height:220px}}

/* 케이스 비교 테이블 */
.table-wrap{{background:#fff;border-radius:12px;overflow:auto;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:28px}}
table{{width:100%;border-collapse:collapse;font-size:.82rem}}
thead th{{background:#1e293b;color:#fff;padding:10px 12px;text-align:left;white-space:nowrap;position:sticky;top:0}}
.model-th{{background:#1d4ed8 !important;min-width:200px}}
tbody tr{{border-bottom:1px solid #f1f5f9}}
tbody tr:hover{{background:#f8fafc}}
.row-all{{}}
.row-miss{{background:#fff7ed}}
td{{padding:9px 12px;vertical-align:middle}}
.case-id{{font-weight:800;color:#94a3b8;width:40px}}
.lang-badge{{display:inline-block;color:#fff;font-size:.7rem;font-weight:700;padding:2px 8px;border-radius:999px}}
.expected{{color:#475569;font-size:.78rem;min-width:160px}}
.model-cell{{min-width:200px}}
.tick{{font-size:.85rem;font-weight:800;margin-right:5px}}
.vuln-text{{font-size:.77rem;color:#334155}}
.sev-mini{{display:inline-block;color:#fff;font-size:.65rem;font-weight:700;padding:1px 6px;border-radius:999px;margin-left:4px}}
.elapsed{{font-size:.72rem;color:#94a3b8;margin-left:4px}}
</style></head><body>

<h1>모델 비교 벤치마크</h1>
<p class="sub">ScanOps · {now} · {n_cases}개 공통 케이스 · {len(summaries)}개 모델 비교</p>

<h2>순위</h2>
<div class="heroes">{hero_cards}</div>

<div class="charts">
  <div class="chart-box">
    <h3>전체 탐지율 비교 (%)</h3>
    <canvas id="cTotal"></canvas>
  </div>
  <div class="chart-box">
    <h3>언어별 탐지율 비교 (%)</h3>
    <canvas id="cLang"></canvas>
  </div>
  <div class="chart-box">
    <h3>평균 응답시간 비교 (초)</h3>
    <canvas id="cTime"></canvas>
  </div>
</div>

<h2>케이스별 상세 비교</h2>
<p style="font-size:.78rem;color:#64748b;margin-bottom:10px;">
  🟡 주황 행 = 한 개 이상의 모델이 미탐지한 케이스
</p>
<div class="table-wrap">
<table>
  <thead>
    <tr>
      <th>#</th><th>언어</th><th>예상 취약점</th>
      {model_headers}
    </tr>
  </thead>
  <tbody>{case_rows}</tbody>
</table>
</div>

<script>
const models   = {models_json};
const detPcts  = {det_pcts_json};
const avgTimes = {avg_times_json};
const palette  = {palette_json};
const langLabels = {lang_labels_json};
const langDatasets = {chart_datasets_json};

// 전체 탐지율 막대
new Chart(document.getElementById('cTotal'), {{
  type: 'bar',
  data: {{ labels: models, datasets: [{{
    label: '탐지율(%)', data: detPcts,
    backgroundColor: palette, borderRadius: 6, borderSkipped: false
  }}] }},
  options: {{ responsive: true,
    plugins: {{ legend: {{ display: false }},
      tooltip: {{ callbacks: {{ label: c => ` ${{c.parsed.y}}%` }} }} }},
    scales: {{ y: {{ beginAtZero: true, max: 100 }}, x: {{ grid: {{ display: false }} }} }} }}
}});

// 언어별 탐지율
new Chart(document.getElementById('cLang'), {{
  type: 'bar',
  data: {{ labels: langLabels, datasets: langDatasets }},
  options: {{ responsive: true,
    plugins: {{ legend: {{ position: 'top', labels: {{ font: {{ size: 10 }} }} }} }},
    scales: {{ y: {{ beginAtZero: true, max: 100 }}, x: {{ grid: {{ display: false }} }} }} }}
}});

// 평균 응답시간
new Chart(document.getElementById('cTime'), {{
  type: 'bar',
  data: {{ labels: models, datasets: [{{
    label: '평균(초)', data: avgTimes,
    backgroundColor: palette, borderRadius: 6, borderSkipped: false
  }}] }},
  options: {{ responsive: true,
    plugins: {{ legend: {{ display: false }},
      tooltip: {{ callbacks: {{ label: c => ` ${{c.parsed.y}}s` }} }} }},
    scales: {{ y: {{ beginAtZero: true }}, x: {{ grid: {{ display: false }} }} }} }}
}});
</script>
</body></html>"""


def main(files: list[Path]) -> None:
    print(f"결과 파일 {len(files)}개 로드 중...")
    summaries = load_summaries(files)
    if not summaries:
        print("비교할 결과 파일이 없습니다. 먼저 어댑터를 실행하세요.")
        print("  예: python scripts/adapters/grok_adapter.py")
        return

    REPORTS.mkdir(exist_ok=True)
    OUTPUT.write_text(build_compare_html(summaries), encoding="utf-8")

    print(f"\n{'─'*55}")
    print(f"비교 모델 {len(summaries)}개:")
    for i, s in enumerate(summaries, 1):
        print(f"  #{i} {s['model_name']:40s} {s['detect_pct']:5.1f}%  {s['avg_time']}s")
    print(f"\n비교 리포트 저장: {OUTPUT}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # 인수로 파일명을 직접 지정한 경우
        target_files = [REPORTS / f for f in sys.argv[1:]]
    else:
        # 기본: reports/ 안의 results_*.json 전부
        target_files = sorted(REPORTS.glob("results_*.json"))

    main(target_files)
