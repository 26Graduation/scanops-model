"""
RAG Benchmark v2 — ScanOps
2단계 파이프라인 결과 벤치마크.

탐지 판정: 1단계(Grok 단독) 응답만 사용 → CVE 오염 없음
CVE 근거:  2단계(ChromaDB) 결과를 별도 컬럼으로 표시
"""

import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchmark_core import CASES, detected, esc, LANG_COLOR, SEVERITY_COLOR, REPORTS
from rag_pipeline import analyze, SIM_THRESHOLD

OUTPUT = REPORTS / "rag_benchmark.html"
MODEL  = "grok-3"

# grok-3 단독 베이스라인 (파서 수정 후 정확한 수치)
GROK_BASELINE = {
    "model":      "grok-3 단독",
    "detected":   20,
    "total":      20,
    "detect_pct": 100.0,
    "avg_time":   5.72,
}


# ── HTML 빌더 ──────────────────────────────────────────────────────────────────

def build_html(results: list[dict]) -> str:
    now        = datetime.now().strftime("%Y-%m-%d %H:%M")
    total      = len(results)
    n_detected = sum(1 for r in results if r["detected"])
    detect_pct = round(n_detected / total * 100, 1)
    valid      = [r for r in results if r["elapsed"] > 0]
    avg_all    = round(sum(r["elapsed"] for r in valid) / len(valid), 2) if valid else 0
    n_with_cve = sum(1 for r in results if r.get("cve_references"))

    det_delta  = detect_pct - GROK_BASELINE["detect_pct"]
    time_delta = avg_all    - GROK_BASELINE["avg_time"]
    det_sign   = "+" if det_delta >= 0 else ""
    time_sign  = "+" if time_delta >= 0 else ""
    det_color  = "#22c55e" if det_delta >= 0 else "#ef4444"
    time_color = "#22c55e" if time_delta <= 0 else "#ef4444"

    lang_stats: dict[str, list] = {}
    for r in results:
        lang_stats.setdefault(r["language"], []).append(r)

    summary_cards = "".join(
        f"""<div class="stat" style="border-top:4px solid {LANG_COLOR.get(lang,'#94a3b8')};">
          <div class="stat-label">{esc(lang)}</div>
          <div class="stat-value" style="color:{LANG_COLOR.get(lang,'#94a3b8')};">
            {round(sum(r['elapsed'] for r in rows)/len(rows),2)}s</div>
          <div class="stat-sub">평균 · {sum(1 for r in rows if r['detected'])}/{len(rows)} 탐지</div>
        </div>"""
        for lang, rows in lang_stats.items()
    )

    sections = ""
    for lang, rows in lang_stats.items():
        color = LANG_COLOR.get(lang, "#94a3b8")
        cards = ""
        for r in rows:
            sev   = r.get("severity", "").upper()
            sc    = SEVERITY_COLOR.get(sev, "#94a3b8")
            ok    = r["detected"]
            tc    = "#22c55e" if ok else "#ef4444"
            ec    = "#22c55e" if r["elapsed"] < 3 else ("#eab308" if r["elapsed"] < 8 else "#ef4444")

            # CVE 근거 섹션
            refs     = r.get("cve_references", [])
            cve_rows = ""
            for c in refs:
                sim_c = "#166534" if c["similarity"] > 0.7 else ("#92400e" if c["similarity"] > 0.6 else "#475569")
                cve_rows += f"""
                <tr>
                  <td>{esc(c['id'])}</td>
                  <td>{esc(c['cwe'])}</td>
                  <td>{esc(c['severity'])}</td>
                  <td style="color:{sim_c};font-weight:700;">{c['similarity']}</td>
                  <td>{esc(c['description'][:90])}…</td>
                </tr>"""

            cve_block = ""
            if refs:
                cve_block = f"""
              <details class="cve-details" open>
                <summary>CVE 근거 {len(refs)}개 (유사도 ≥ {SIM_THRESHOLD})</summary>
                <table class="cve-table">
                  <thead><tr><th>CVE ID</th><th>CWE</th><th>심각도</th><th>유사도</th><th>설명</th></tr></thead>
                  <tbody>{cve_rows}</tbody>
                </table>
              </details>"""
            else:
                cve_block = f'<div class="no-cve">CVE 근거 없음 (유사도 {SIM_THRESHOLD} 미만)</div>'

            cards += f"""
            <div class="case-card">
              <div class="case-header">
                <span class="case-num">#{r['id']}</span>
                <span class="expected">예상 취약점: {esc(r['expected_vuln'])}</span>
                <span class="tick" style="color:{tc};">{'✓ 탐지됨' if ok else '✗ 미탐지'}</span>
              </div>
              <div class="code-block"><pre>{esc(r['code'])}</pre></div>
              <div class="response-grid">
                <div class="resp-item">
                  <span class="resp-label">취약점</span>
                  <span class="resp-value">{esc(r.get('vulnerability','—'))}</span>
                </div>
                <div class="resp-item">
                  <span class="resp-label">심각도</span>
                  <span class="sev-badge" style="background:{sc};">{sev or '—'}</span>
                </div>
                <div class="resp-item full">
                  <span class="resp-label">공격 시나리오</span>
                  <span class="resp-value">{esc(r.get('attack','—'))}</span>
                </div>
                <div class="resp-item full">
                  <span class="resp-label">수정 코드</span>
                  <pre class="fix-block">{esc(r.get('fix','—'))}</pre>
                </div>
                <div class="resp-item">
                  <span class="resp-label">응답시간 (1단계)</span>
                  <span class="resp-value" style="color:{ec};font-weight:700;">{r['elapsed']}s</span>
                </div>
              </div>
              {cve_block}
            </div>"""

        sections += f'<section><div class="lang-header" style="background:{color};">{esc(lang)}</div>{cards}</section>'

    chart_labels = json.dumps(list(lang_stats.keys()))
    chart_times  = json.dumps([round(sum(r["elapsed"] for r in v)/len(v),2) for v in lang_stats.values()])
    chart_det    = json.dumps([round(sum(1 for r in v if r["detected"])/len(v)*100,1) for v in lang_stats.values()])
    chart_colors = json.dumps([LANG_COLOR.get(l,"#94a3b8") for l in lang_stats])

    return f"""<!DOCTYPE html><html lang="ko"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RAG 파이프라인 v2 벤치마크 — ScanOps</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f4f8;color:#1e293b;padding:24px}}
h1{{font-size:1.6rem;font-weight:700;margin-bottom:4px}}
.sub{{color:#64748b;font-size:.88rem;margin-bottom:24px}}
code{{font-family:monospace;font-size:.85em;background:#f1f5f9;padding:1px 5px;border-radius:4px}}
.rag-badge{{display:inline-block;background:#0891b2;color:#fff;font-size:.78rem;font-weight:700;padding:3px 12px;border-radius:999px;margin-left:8px;vertical-align:middle}}
.pipeline-note{{background:#f0f9ff;border:1px solid #bae6fd;border-radius:10px;padding:14px 18px;margin-bottom:20px;font-size:.85rem;color:#0369a1;line-height:1.7}}
.pipeline-note strong{{color:#0c4a6e}}

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

.cve-details{{background:#f0f9ff;border-top:2px solid #bae6fd}}
.cve-details summary{{padding:9px 16px;font-size:.78rem;font-weight:700;color:#0369a1;cursor:pointer;user-select:none}}
.cve-table{{width:100%;border-collapse:collapse;font-size:.75rem}}
.cve-table th{{background:#e0f2fe;padding:6px 12px;text-align:left;font-weight:700;color:#0369a1}}
.cve-table td{{padding:6px 12px;border-bottom:1px solid #e0f2fe;color:#334155;vertical-align:top}}
.cve-table tr:last-child td{{border-bottom:none}}
.no-cve{{padding:9px 16px;font-size:.75rem;color:#94a3b8;background:#fafafa;border-top:1px solid #f1f5f9}}
</style></head><body>

<h1>RAG 파이프라인 v2 <span class="rag-badge">2단계 파이프라인</span></h1>
<p class="sub">ScanOps · {now} · {total}개 케이스 · 모델: <code>{MODEL}</code> · CVE top-3 근거</p>

<div class="pipeline-note">
  <strong>📐 2단계 파이프라인 구조</strong><br>
  1단계: 코드 → Grok 단독 탐지 (CVE 컨텍스트 없음) → 취약점/CWE 판별<br>
  2단계: 탐지된 CWE + 취약점명 → ChromaDB 검색 → 유사 CVE 근거 반환 (유사도 {SIM_THRESHOLD} 이상)<br>
  <strong>탐지율은 1단계 결과로만 판정</strong> — CVE 컨텍스트 오염 없음
</div>

<div class="top-stats">
  <div class="hero"><div class="hero-label">총 케이스</div><div class="hero-value">{total}</div></div>
  <div class="hero" style="background:#166534;"><div class="hero-label">탐지</div>
    <div class="hero-value">{n_detected}<span style="font-size:1rem;opacity:.8;"> / {total}</span></div></div>
  <div class="hero" style="background:#1d4ed8;"><div class="hero-label">탐지율</div>
    <div class="hero-value">{detect_pct}%</div></div>
  <div class="hero" style="background:#0891b2;"><div class="hero-label">CVE 근거 확보</div>
    <div class="hero-value">{n_with_cve}<span style="font-size:1rem;opacity:.8;"> / {total}</span></div></div>
</div>

<div class="baseline-row">
  <div><div class="bl-label">베이스라인 (grok-3 단독)</div>
    <div class="bl-val">{GROK_BASELINE['detect_pct']}% 탐지 · {GROK_BASELINE['avg_time']}s 평균</div></div>
  <div><div class="bl-label">탐지율 변화</div>
    <div class="bl-delta" style="color:{det_color};">{det_sign}{det_delta:.1f}%p</div></div>
  <div><div class="bl-label">응답시간 변화</div>
    <div class="bl-delta" style="color:{time_color};">{time_sign}{time_delta:.2f}s</div></div>
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


def main() -> None:
    REPORTS.mkdir(exist_ok=True)
    results = []

    print(f"[RAG v2] 모델: {MODEL}  |  2단계 파이프라인  |  케이스: {len(CASES)}개")
    print("─" * 60)

    for case in CASES:
        print(f"[{case['id']:02d}/20] [{case['language']}] {case['expected_vuln']}")
        try:
            result = analyze(case["language"], case["code"], model=MODEL)
        except Exception as e:
            print(f"  오류: {e}\n")
            results.append({**case, "vulnerability": "—", "severity": "—",
                             "attack": "—", "fix": "—", "elapsed": 0.0,
                             "detected": False, "cve_references": []})
            continue

        # 탐지 판정: 1단계 응답으로만 (benchmark_core의 detected 함수 사용)
        from benchmark_core import parse_response
        parsed = parse_response(result["raw_response"])
        ok     = detected(parsed, case)

        entry = {**case, **result, "detected": ok}
        results.append(entry)

        tick     = "✓" if ok else "✗"
        refs     = result["cve_references"]
        cve_info = f"CVE근거 {len(refs)}개" if refs else "CVE근거 없음"
        print(f"  {tick} {result['vulnerability'][:48]}  [{result['severity']}]  {result['elapsed']}s  [{cve_info}]\n")

    valid      = [r for r in results if r["elapsed"] > 0]
    n_det      = sum(1 for r in results if r["detected"])
    n_cve      = sum(1 for r in results if r.get("cve_references"))
    total      = len(results)
    avg_t      = round(sum(r["elapsed"] for r in valid) / len(valid), 2) if valid else 0

    # JSON 저장 (benchmark_compare.py 호환)
    summary = {
        "model_name": f"ScanOps — RAG v2 (grok-3)",
        "timestamp":  datetime.now().isoformat(),
        "total":      total,
        "detected":   n_det,
        "detect_pct": round(n_det / total * 100, 1),
        "avg_time":   avg_t,
        "results":    results,
    }
    json_out = REPORTS / "results_RAG_v2_grok3.json"
    json_out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    OUTPUT.write_text(build_html(results), encoding="utf-8")

    print("─" * 60)
    print(f"[RAG v2] 탐지율:      {n_det}/{total} ({summary['detect_pct']}%)")
    print(f"[RAG v2] CVE 근거 확보: {n_cve}/{total}개 케이스")
    print(f"[RAG v2] 평균 응답시간: {avg_t}s")
    print(f"HTML: {OUTPUT}")
    print(f"JSON: {json_out}")


if __name__ == "__main__":
    main()
