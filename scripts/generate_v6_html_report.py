"""
v6 비교 리포트(HTML) 생성기 — ScanOps(QLoRA+RAG+Neo4j 코드그래프) vs Grok-3
==========================================================================
두 벤치마크 결과를 하나의 HTML로 합쳐서 시각적으로 비교한다:
  1) NVD 2026 100케이스 (scripts/benchmark_v5_cases.py + benchmark_v5.py)
     — 단일 코드 취약점 탐지율/오탐률 비교
  2) 코드그래프(Neo4j) 100케이스 (scripts/graph_benchmark_cases.py +
     benchmark_graph_vs_grok.py) — 멀티파일 데이터 흐름(taint) 추적 비교

reports/rag_benchmark.html 스타일(케이스 카드 + Chart.js)을 따른다.

실행:
  source .venv/bin/activate
  python scripts/generate_v6_html_report.py
출력:
  reports/v6_scanops_vs_grok_report.html
"""
from __future__ import annotations

import html
import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

from scripts.benchmark_v5_cases import CASES as V5_CASES
from scripts.graph_benchmark_cases import CASES as GRAPH_CASES

REPORTS = BASE / "reports"
OUT = REPORTS / "v6_scanops_vs_grok_report.html"

graph_result = json.loads((REPORTS / "results_graph_vs_grok.json").read_text())
v5_result = json.loads((REPORTS / "results_v5_false_positive_benchmark.json").read_text())

graph_cases_by_id = {c["id"]: c for c in GRAPH_CASES}
graph_rows_by_id = {r["id"]: r for r in graph_result["cases"]}

v5_cases_by_id = {c["id"]: c for c in V5_CASES}
v5_systems = {s["model_name"]: s for s in v5_result["systems"]}
v5_so = next(v for k, v in v5_systems.items() if "ScanOps" in k)
v5_gk = next(v for k, v in v5_systems.items() if "Grok" in k)
v5_so_by_id = {r["id"]: r for r in v5_so["results"]}
v5_gk_by_id = {r["id"]: r for r in v5_gk["results"]}


def esc(s) -> str:
    return html.escape(str(s), quote=True)


# ─────────────────────────────────────────────────────────────────────────
# Neo4j 그래프 시각화 (SVG) — 안전/위험 두 시나리오 + 2-hop 체인
# ─────────────────────────────────────────────────────────────────────────

def svg_schema() -> str:
    return """
<svg viewBox="0 0 760 230" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:760px">
  <defs>
    <marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
      <path d="M0,0 L8,3 L0,6 Z" fill="#64748b"/>
    </marker>
  </defs>
  <style>
    .node{rx:8;stroke-width:1.5}
    .lbl{font-family:monospace;font-size:12px;fill:#1e293b;text-anchor:middle}
    .rel{font-family:monospace;font-size:10px;fill:#64748b;text-anchor:middle}
  </style>
  <rect x="20" y="20" width="100" height="36" class="node" fill="#e0f2fe" stroke="#0891b2"/>
  <text x="70" y="42" class="lbl">File</text>

  <rect x="180" y="20" width="110" height="36" class="node" fill="#fef9c3" stroke="#ca8a04"/>
  <text x="235" y="42" class="lbl">Variable</text>

  <rect x="360" y="20" width="150" height="36" class="node" fill="#dcfce7" stroke="#16a34a"/>
  <text x="435" y="42" class="lbl">StaticImport</text>

  <rect x="360" y="90" width="150" height="36" class="node" fill="#fee2e2" stroke="#dc2626"/>
  <text x="435" y="112" class="lbl">UserInput</text>

  <rect x="180" y="160" width="110" height="36" class="node" fill="#fef9c3" stroke="#ca8a04"/>
  <text x="235" y="182" class="lbl">Variable (다른 파일)</text>

  <rect x="580" y="160" width="160" height="36" class="node" fill="#ede9fe" stroke="#7c3aed"/>
  <text x="660" y="182" class="lbl">DangerousSink</text>

  <line x1="120" y1="38" x2="180" y2="38" stroke="#64748b" marker-end="url(#arrow)"/>
  <text x="150" y="30" class="rel">DECLARES</text>

  <line x1="290" y1="38" x2="360" y2="38" stroke="#16a34a" marker-end="url(#arrow)"/>
  <text x="325" y="30" class="rel">RESOLVES_TO</text>

  <line x1="435" y1="90" x2="290" y2="50" stroke="#dc2626" marker-end="url(#arrow)"/>
  <text x="400" y="78" class="rel">FLOWS_TO</text>

  <line x1="235" y1="56" x2="235" y2="160" stroke="#ca8a04" marker-end="url(#arrow)"/>
  <text x="170" y="110" class="rel">PASSED_AS_PROP</text>

  <line x1="290" y1="178" x2="580" y2="178" stroke="#7c3aed" marker-end="url(#arrow)"/>
  <text x="435" y="170" class="rel">FLOWS_TO</text>
</svg>
"""


def svg_safe_instance() -> str:
    return """
<svg viewBox="0 0 700 170" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:700px">
  <defs>
    <marker id="arrowS" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
      <path d="M0,0 L8,3 L0,6 Z" fill="#16a34a"/>
    </marker>
  </defs>
  <style>.lbl{font-family:monospace;font-size:11.5px;fill:#1e293b;text-anchor:middle}
  .rel{font-family:monospace;font-size:10px;fill:#16a34a;text-anchor:middle;font-weight:700}</style>

  <rect x="10" y="60" width="170" height="40" rx="8" fill="#dcfce7" stroke="#16a34a" stroke-width="1.5"/>
  <text x="95" y="84" class="lbl">asset.svg (StaticImport)</text>

  <rect x="240" y="60" width="170" height="40" rx="8" fill="#fef9c3" stroke="#ca8a04" stroke-width="1.5"/>
  <text x="325" y="84" class="lbl">Root.tsx: RawAsset</text>

  <rect x="470" y="60" width="160" height="40" rx="8" fill="#fef9c3" stroke="#ca8a04" stroke-width="1.5"/>
  <text x="550" y="84" class="lbl">Leaf.tsx: val</text>

  <rect x="470" y="10" width="160" height="34" rx="8" fill="#ede9fe" stroke="#7c3aed" stroke-width="1.5"/>
  <text x="550" y="32" class="lbl">innerHTML (Sink)</text>

  <line x1="180" y1="80" x2="240" y2="80" stroke="#16a34a" marker-end="url(#arrowS)"/>
  <text x="210" y="72" class="rel">RESOLVES_TO</text>

  <line x1="410" y1="80" x2="470" y2="80" stroke="#16a34a" marker-end="url(#arrowS)"/>
  <text x="440" y="72" class="rel">PASSED_AS_PROP</text>

  <line x1="550" y1="60" x2="550" y2="44" stroke="#16a34a" marker-end="url(#arrowS)"/>

  <rect x="10" y="120" width="300" height="34" rx="17" fill="#16a34a"/>
  <text x="160" y="142" font-family="monospace" font-size="12" fill="#fff" text-anchor="middle" font-weight="700">verdict = SAFE (오탐 억제)</text>
</svg>
"""


def svg_tainted_instance() -> str:
    return """
<svg viewBox="0 0 700 170" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:700px">
  <defs>
    <marker id="arrowT" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
      <path d="M0,0 L8,3 L0,6 Z" fill="#dc2626"/>
    </marker>
  </defs>
  <style>.lbl{font-family:monospace;font-size:11.5px;fill:#1e293b;text-anchor:middle}
  .rel{font-family:monospace;font-size:10px;fill:#dc2626;text-anchor:middle;font-weight:700}</style>

  <rect x="10" y="60" width="220" height="40" rx="8" fill="#fee2e2" stroke="#dc2626" stroke-width="1.5"/>
  <text x="120" y="84" class="lbl">req.query.target (UserInput)</text>

  <rect x="300" y="60" width="170" height="40" rx="8" fill="#fef9c3" stroke="#ca8a04" stroke-width="1.5"/>
  <text x="385" y="84" class="lbl">Root.tsx: val</text>

  <rect x="540" y="60" width="150" height="40" rx="8" fill="#ede9fe" stroke="#7c3aed" stroke-width="1.5"/>
  <text x="615" y="84" class="lbl">fetch (Sink)</text>

  <line x1="230" y1="80" x2="300" y2="80" stroke="#dc2626" marker-end="url(#arrowT)"/>
  <text x="265" y="72" class="rel">FLOWS_TO</text>

  <line x1="470" y1="80" x2="540" y2="80" stroke="#dc2626" marker-end="url(#arrowT)"/>
  <text x="505" y="72" class="rel">FLOWS_TO</text>

  <rect x="10" y="120" width="340" height="34" rx="17" fill="#dc2626"/>
  <text x="180" y="142" font-family="monospace" font-size="12" fill="#fff" text-anchor="middle" font-weight="700">verdict = TAINTED (SSRF 위험 유지)</text>
</svg>
"""


def svg_chain_instance() -> str:
    return """
<svg viewBox="0 0 760 170" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:760px">
  <defs>
    <marker id="arrowC" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
      <path d="M0,0 L8,3 L0,6 Z" fill="#dc2626"/>
    </marker>
  </defs>
  <style>.lbl{font-family:monospace;font-size:11px;fill:#1e293b;text-anchor:middle}
  .rel{font-family:monospace;font-size:9.5px;fill:#dc2626;text-anchor:middle;font-weight:700}</style>

  <rect x="0" y="60" width="150" height="40" rx="8" fill="#fee2e2" stroke="#dc2626" stroke-width="1.5"/>
  <text x="75" y="84" class="lbl">window.location (UserInput)</text>

  <rect x="200" y="60" width="120" height="40" rx="8" fill="#fef9c3" stroke="#ca8a04" stroke-width="1.5"/>
  <text x="260" y="84" class="lbl">Root.tsx: val</text>

  <rect x="380" y="60" width="120" height="40" rx="8" fill="#fef9c3" stroke="#ca8a04" stroke-width="1.5"/>
  <text x="440" y="84" class="lbl">Mid.tsx: val</text>

  <rect x="560" y="60" width="120" height="40" rx="8" fill="#fef9c3" stroke="#ca8a04" stroke-width="1.5"/>
  <text x="620" y="84" class="lbl">Leaf.tsx: val</text>

  <rect x="560" y="0" width="190" height="34" rx="8" fill="#ede9fe" stroke="#7c3aed" stroke-width="1.5"/>
  <text x="655" y="22" class="lbl">dangerouslySetInnerHTML</text>

  <line x1="150" y1="80" x2="200" y2="80" stroke="#dc2626" marker-end="url(#arrowC)"/>
  <text x="175" y="72" class="rel">FLOWS_TO</text>
  <line x1="320" y1="80" x2="380" y2="80" stroke="#dc2626" marker-end="url(#arrowC)"/>
  <text x="350" y="72" class="rel">PASSED_AS_PROP</text>
  <line x1="500" y1="80" x2="560" y2="80" stroke="#dc2626" marker-end="url(#arrowC)"/>
  <text x="530" y="72" class="rel">PASSED_AS_PROP</text>
  <line x1="650" y1="60" x2="650" y2="34" stroke="#dc2626" marker-end="url(#arrowC)"/>

  <rect x="0" y="120" width="460" height="34" rx="17" fill="#dc2626"/>
  <text x="230" y="142" font-family="monospace" font-size="12" fill="#fff" text-anchor="middle" font-weight="700">verdict = TAINTED — 2-hop prop 체인도 끝까지 추적 (XSS 위험 유지)</text>
</svg>
"""


# ─────────────────────────────────────────────────────────────────────────
# 케이스 카드 (그래프 벤치마크)
# ─────────────────────────────────────────────────────────────────────────

def files_block_html(files: dict[str, str]) -> str:
    parts = []
    for fn, content in files.items():
        parts.append(
            f'<div class="file-tag">{esc(fn)}</div>'
            f'<pre>{esc(content.rstrip())}</pre>'
        )
    return "".join(parts)


def graph_case_card(case_id: str, idx: int) -> str:
    c = graph_cases_by_id[case_id]
    r = graph_rows_by_id[case_id]
    exp = "VULNERABLE" if c["expected_vulnerable"] else "SAFE"
    so_v = "VULNERABLE" if r["scanops"]["vulnerable"] else "SAFE"
    gk_v = "VULNERABLE" if r["grok"]["vulnerable"] else "SAFE"
    so_ok = r["scanops"]["correct"]
    gk_ok = r["grok"]["correct"]
    cve_badge = f'<span class="cve-tag">{esc(c["cve"])}</span>' if c.get("cve") else ""

    return f"""
<div class="case-card">
  <div class="case-header">
    <span class="case-num">#{idx}</span>
    <span class="expected">{esc(c['title'])} {cve_badge}</span>
    <span class="tick" style="color:{'#22c55e' if exp=='VULNERABLE' else '#64748b'};">정답: {exp}</span>
  </div>
  <div class="code-block">{files_block_html(c['files'])}</div>
  <div class="verdict-grid">
    <div class="verdict-item {'ok' if so_ok else 'bad'}">
      <span class="resp-label">ScanOps (그래프 엔진)</span>
      <span class="verdict-val">{so_v} {'✅' if so_ok else '❌'}</span>
      <span class="verdict-sub">verdicts={r['scanops']['verdicts']}</span>
    </div>
    <div class="verdict-item {'ok' if gk_ok else 'bad'}">
      <span class="resp-label">Grok-3-mini (코드만)</span>
      <span class="verdict-val">{gk_v} {'✅' if gk_ok else '❌'}</span>
      <span class="verdict-sub">raw: {esc(r['grok'].get('raw',''))}</span>
    </div>
  </div>
</div>
"""


# 보여줄 대표 케이스 선정: 안전 1 + 위험(SSRF) 1 + 위험(2-hop XSS) 1 + Grok이
# 틀리고 ScanOps만 맞춘 실제 CVE 기반 케이스 다수
showcase_ids = [
    "cve26-xss-02",  # 안전: 정적 import(asset.svg) -> innerHTML, hop=1
    "cve26-ssrf-01",  # 위험: req.query -> fetch, hop=0 (SSRF)
    "cve26-xss-03",  # 위험: window.location -> 2-hop prop -> dangerouslySetInnerHTML
]
extra_wrong_for_grok = [
    cid for cid in graph_cases_by_id
    if cid.startswith("cve26") and graph_rows_by_id[cid]["scanops"]["correct"]
    and not graph_rows_by_id[cid]["grok"]["correct"] and cid not in showcase_ids
][:6]
showcase_ids += extra_wrong_for_grok

graph_showcase_html = "".join(
    graph_case_card(cid, i + 1) for i, cid in enumerate(showcase_ids)
)


def _ok_cell(ok: bool) -> str:
    color = "#16a34a" if ok else "#dc2626"
    mark = "✓" if ok else "✗"
    return f"<td style='color:{color};font-weight:700'>{mark}</td>"


def graph_table_rows() -> str:
    rows = []
    for c in GRAPH_CASES:
        r = graph_rows_by_id[c["id"]]
        so_ok = r["scanops"]["correct"]
        gk_ok = r["grok"]["correct"]
        group = "CVE-2026" if c["id"].startswith("cve26") else "구조"
        rows.append(
            "<tr>"
            f"<td>{esc(c['id'])}</td><td>{esc(group)}</td>"
            f"<td>{esc(c.get('cve') or '-')}</td>"
            f"<td>{esc(c['category'])}/{esc(c['sink'])}</td>"
            f"<td>{c['hop']}</td><td>{'Y' if c['alias'] else '-'}</td>"
            f"<td>{'VULN' if c['expected_vulnerable'] else 'SAFE'}</td>"
            f"{_ok_cell(so_ok)}{_ok_cell(gk_ok)}"
            "</tr>"
        )
    return "".join(rows)


# ─────────────────────────────────────────────────────────────────────────
# 케이스 카드 (NVD 2026 100케이스) — Grok이 놓치고 ScanOps가 잡은 사례 위주
# ─────────────────────────────────────────────────────────────────────────

def v5_showcase_ids(n: int = 6) -> list[int]:
    ids = []
    for cid, so_r in v5_so_by_id.items():
        gk_r = v5_gk_by_id[cid]
        case = v5_cases_by_id[cid]
        if case["label"] != "vuln":
            continue
        if so_r["flagged"] and not gk_r["flagged"]:
            ids.append(cid)
    return ids[:n]


def v5_case_card(cid: int, idx: int) -> str:
    case = v5_cases_by_id[cid]
    so_r = v5_so_by_id[cid]
    gk_r = v5_gk_by_id[cid]
    cve_badge = f'<span class="cve-tag">{esc(case["cve"])}</span>' if case.get("cve") and case["cve"] != "-" else ""
    return f"""
<div class="case-card">
  <div class="case-header">
    <span class="case-num">#{idx}</span>
    <span class="expected">[{esc(case['language'])}] 예상 취약점: {esc(case['expected_vuln'])} {cve_badge}</span>
    <span class="tick" style="color:#22c55e;">정답: VULNERABLE</span>
  </div>
  <div class="code-block"><div class="file-tag">입력 코드</div><pre>{esc(case['code'])}</pre></div>
  <div class="verdict-grid">
    <div class="verdict-item {'ok' if so_r['flagged'] else 'bad'}">
      <span class="resp-label">ScanOps (QLoRA v4 + 게이트)</span>
      <span class="verdict-val">{'VULNERABLE ✅' if so_r['flagged'] else 'SAFE(미탐) ❌'}</span>
      <span class="verdict-sub">{esc(so_r['raw'])} · {so_r['elapsed']}s</span>
    </div>
    <div class="verdict-item {'ok' if gk_r['flagged'] else 'bad'}">
      <span class="resp-label">Grok-3-mini</span>
      <span class="verdict-val">{'VULNERABLE ✅' if gk_r['flagged'] else 'SAFE(미탐) ❌'}</span>
      <span class="verdict-sub">{esc(gk_r['raw'])} · {gk_r['elapsed']}s</span>
    </div>
  </div>
</div>
"""


v5_cards_html = "".join(
    v5_case_card(cid, i + 1) for i, cid in enumerate(v5_showcase_ids(6))
)


def v5_table_rows() -> str:
    rows = []
    for cid, case in v5_cases_by_id.items():
        so_r = v5_so_by_id[cid]
        gk_r = v5_gk_by_id[cid]
        expected_vuln = case["label"] == "vuln"
        so_ok = so_r["flagged"] == expected_vuln
        gk_ok = gk_r["flagged"] == expected_vuln
        rows.append(
            f"<tr><td>{cid}</td><td>{esc(case['language'])}</td>"
            f"<td>{esc(case.get('cve') or '-')}</td>"
            f"<td>{esc(case['expected_vuln'])}</td>"
            f"<td>{'VULN' if expected_vuln else 'SAFE'}</td>"
            f"{_ok_cell(so_ok)}{_ok_cell(gk_ok)}"
            "</tr>"
        )
    return "".join(rows)


# ─────────────────────────────────────────────────────────────────────────
# sink별 Grok 정확도 (차트용)
# ─────────────────────────────────────────────────────────────────────────

sink_stats: dict[str, list[int]] = {}
for c in GRAPH_CASES:
    r = graph_rows_by_id[c["id"]]
    s = sink_stats.setdefault(c["sink"], [0, 0])
    s[0] += 1
    s[1] += r["grok"]["correct"]
sink_labels = list(sink_stats.keys())
sink_grok_acc = [round(100 * v[1] / v[0], 1) for v in sink_stats.values()]

group_stats = graph_result["breakdown"]

html_doc = f"""<!DOCTYPE html><html lang="ko"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ScanOps v6 (QLoRA+RAG+Neo4j) vs Grok-3 종합 비교 리포트</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f0f4f8;color:#1e293b;padding:24px}}
h1{{font-size:1.6rem;font-weight:700;margin-bottom:4px}}
h2{{font-size:1.15rem;font-weight:700;margin:36px 0 14px}}
h3{{font-size:.95rem;font-weight:700;color:#334155;margin-bottom:10px}}
.sub{{color:#64748b;font-size:.88rem;margin-bottom:24px}}
code{{font-family:monospace;font-size:.85em;background:#f1f5f9;padding:1px 5px;border-radius:4px}}
.badge{{display:inline-block;background:#0891b2;color:#fff;font-size:.78rem;font-weight:700;padding:3px 12px;border-radius:999px;margin-left:8px;vertical-align:middle}}
.badge.alt{{background:#7c3aed}}
.note{{background:#f0f9ff;border:1px solid #bae6fd;border-radius:10px;padding:14px 18px;margin-bottom:20px;font-size:.85rem;color:#0369a1;line-height:1.7}}
.note strong{{color:#0c4a6e}}

.top-stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px}}
.hero{{background:#1e293b;color:#fff;border-radius:12px;padding:18px 28px;flex:1;min-width:150px}}
.hero-label{{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;opacity:.6}}
.hero-value{{font-size:2rem;font-weight:800;margin-top:2px}}

.charts{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px}}
.chart-box{{background:#fff;border-radius:12px;padding:20px;flex:1;min-width:280px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
.chart-box h3{{font-size:.9rem;font-weight:600;color:#334155;margin-bottom:14px}}
canvas{{max-height:230px}}

.graph-box{{background:#fff;border-radius:12px;padding:20px 24px;margin-bottom:16px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
.graph-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}}
@media (max-width:900px){{.graph-grid{{grid-template-columns:1fr}}}}

section{{margin-bottom:28px}}
.case-card{{background:#fff;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.07);border-radius:10px;margin-bottom:10px}}
.case-header{{display:flex;align-items:center;gap:10px;padding:10px 16px;background:#f8fafc;border-bottom:1px solid #e2e8f0;flex-wrap:wrap}}
.case-num{{font-weight:800;font-size:.8rem;color:#64748b}}
.expected{{font-size:.78rem;color:#475569;flex:1}}
.tick{{font-size:.78rem;font-weight:700}}
.cve-tag{{display:inline-block;background:#fef3c7;color:#92400e;font-size:.68rem;font-weight:700;padding:1px 8px;border-radius:999px;margin-left:6px}}
.code-block{{background:#0f172a;padding:10px 16px}}
.file-tag{{color:#94a3b8;font-family:monospace;font-size:.68rem;margin-top:6px}}
.code-block pre{{color:#e2e8f0;font-family:monospace;font-size:.78rem;line-height:1.55;white-space:pre-wrap;word-break:break-word;margin-bottom:4px}}
.verdict-grid{{display:grid;grid-template-columns:1fr 1fr}}
.verdict-item{{padding:10px 16px;border-right:1px solid #f1f5f9;display:flex;flex-direction:column;gap:2px}}
.verdict-item.ok{{background:#f0fdf4}}
.verdict-item.bad{{background:#fef2f2}}
.resp-label{{font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8}}
.verdict-val{{font-size:.88rem;font-weight:700;color:#1e293b}}
.verdict-sub{{font-size:.72rem;color:#64748b;font-family:monospace}}

table.data{{width:100%;border-collapse:collapse;font-size:.74rem;background:#fff;border-radius:10px;overflow:hidden}}
table.data th{{background:#1e293b;color:#fff;padding:7px 10px;text-align:left;position:sticky;top:0}}
table.data td{{padding:6px 10px;border-bottom:1px solid #f1f5f9}}
table.data tr:hover td{{background:#f8fafc}}
.table-scroll{{max-height:480px;overflow:auto;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
</style></head><body>

<h1>ScanOps v6 (QLoRA + RAG + Neo4j 코드그래프) vs Grok-3 <span class="badge">종합 비교 리포트</span></h1>
<p class="sub">ScanOps · 2026-06-23 · 두 개의 100케이스 벤치마크(단일코드 탐지 / 멀티파일 그래프 추적)를 한 화면에서 비교</p>

<div class="note">
  <strong>📐 두 벤치마크 구조</strong><br>
  ① <strong>NVD 2026 100케이스</strong>: 단일 코드 스니펫에서 취약점 탐지율/오탐률 비교 (양성 50=2026년 5~6월 실제 NVD CVE, 음성 50=mitigation 적용 안전코드)<br>
  ② <strong>코드그래프(Neo4j) 100케이스</strong>: 여러 파일에 걸쳐 사용자 입력이 위험 sink까지 도달하는지 추적하는 능력 비교 (50=2026 NVD XSS/SSRF CVE 기반, 50=sink×prop-hop×alias 구조 조합)
</div>

<div class="top-stats">
  <div class="hero" style="background:#1d4ed8;"><div class="hero-label">① NVD100 · ScanOps 탐지율</div><div class="hero-value">{v5_so['metrics']['detection_recall']}%</div></div>
  <div class="hero" style="background:#475569;"><div class="hero-label">① NVD100 · Grok 탐지율</div><div class="hero-value">{v5_gk['metrics']['detection_recall']}%</div></div>
  <div class="hero" style="background:#166534;"><div class="hero-label">② 그래프100 · ScanOps 정확도</div><div class="hero-value">{graph_result['scanops_accuracy']}%</div></div>
  <div class="hero" style="background:#b91c1c;"><div class="hero-label">② 그래프100 · Grok 정확도</div><div class="hero-value">{graph_result['grok_accuracy']}%</div></div>
</div>

<h2>① NVD 2026 100케이스 — 단일코드 탐지 벤치마크</h2>
<div class="charts">
  <div class="chart-box"><h3>탐지율 / 오탐률 / 정확도 (%)</h3><canvas id="c1"></canvas></div>
  <div class="chart-box"><h3>평균 응답시간 (초)</h3><canvas id="c2"></canvas></div>
</div>

<h3>Grok이 놓치고 ScanOps가 잡은 사례 (입력 → 출력)</h3>
{v5_cards_html}

<h3>전체 100케이스 결과표</h3>
<div class="table-scroll">
<table class="data">
<thead><tr><th>id</th><th>언어</th><th>CVE</th><th>예상 취약점</th><th>정답</th><th>ScanOps</th><th>Grok</th></tr></thead>
<tbody>{v5_table_rows()}</tbody>
</table>
</div>

<h2>② 코드그래프(Neo4j) 100케이스 — 멀티파일 데이터흐름 추적 벤치마크</h2>

<div class="charts">
  <div class="chart-box"><h3>전체/그룹별 정확도 (%)</h3><canvas id="c3"></canvas></div>
  <div class="chart-box"><h3>sink 종류별 Grok 정확도 (%) — ScanOps는 전부 100%</h3><canvas id="c4"></canvas></div>
</div>

<h3>Neo4j 코드 그래프 구조 시각화</h3>
<div class="graph-box">
  <p style="font-size:.82rem;color:#64748b;margin-bottom:10px">scanops/core/code_graph.py 가 추출하는 그래프 스키마 — File→Variable→StaticImport/UserInput, Variable→(Prop)→Variable→DangerousSink</p>
  {svg_schema()}
</div>
<div class="graph-grid">
  <div class="graph-box">
    <h3 style="color:#16a34a">예시 ① 정적 import → 오탐 억제 (cve26-xss-02)</h3>
    {svg_safe_instance()}
  </div>
  <div class="graph-box">
    <h3 style="color:#dc2626">예시 ② 사용자 입력 → SSRF 위험 유지 (cve26-ssrf-01)</h3>
    {svg_tainted_instance()}
  </div>
</div>
<div class="graph-box">
  <h3 style="color:#dc2626">예시 ③ 2-hop prop 체인도 끝까지 추적 (cve26-xss-03)</h3>
  {svg_chain_instance()}
</div>

<h3>대표 케이스 (입력 코드 → ScanOps/Grok 판정)</h3>
{graph_showcase_html}

<h3>전체 100케이스 결과표</h3>
<div class="table-scroll">
<table class="data">
<thead><tr><th>id</th><th>그룹</th><th>CVE</th><th>카테고리/sink</th><th>hop</th><th>alias</th><th>정답</th><th>ScanOps</th><th>Grok</th></tr></thead>
<tbody>{graph_table_rows()}</tbody>
</table>
</div>

<script>
new Chart(document.getElementById('c1'),{{type:'bar',data:{{
  labels:['탐지율(Recall)','오탐률(FPR)','정확도'],
  datasets:[
    {{label:'ScanOps',data:[{v5_so['metrics']['detection_recall']},{v5_so['metrics']['false_positive_rate']},{v5_so['metrics']['accuracy']}],backgroundColor:'#1d4ed8',borderRadius:5}},
    {{label:'Grok-3-mini',data:[{v5_gk['metrics']['detection_recall']},{v5_gk['metrics']['false_positive_rate']},{v5_gk['metrics']['accuracy']}],backgroundColor:'#64748b',borderRadius:5}}
  ]}},options:{{responsive:true,scales:{{y:{{beginAtZero:true,max:100}}}}}}}});

new Chart(document.getElementById('c2'),{{type:'bar',data:{{
  labels:['평균 응답시간(초)'],
  datasets:[
    {{label:'ScanOps',data:[{v5_so['metrics']['avg_time']}],backgroundColor:'#1d4ed8',borderRadius:5}},
    {{label:'Grok-3-mini',data:[{v5_gk['metrics']['avg_time']}],backgroundColor:'#64748b',borderRadius:5}}
  ]}},options:{{responsive:true,scales:{{y:{{beginAtZero:true}}}}}}}});

new Chart(document.getElementById('c3'),{{type:'bar',data:{{
  labels:['전체 100','CVE-2026 50','구조패턴 50'],
  datasets:[
    {{label:'ScanOps',data:[{graph_result['scanops_accuracy']},{group_stats['cve_2026']['scanops_accuracy']},{group_stats['structural']['scanops_accuracy']}],backgroundColor:'#166534',borderRadius:5}},
    {{label:'Grok-3-mini',data:[{graph_result['grok_accuracy']},{group_stats['cve_2026']['grok_accuracy']},{group_stats['structural']['grok_accuracy']}],backgroundColor:'#b91c1c',borderRadius:5}}
  ]}},options:{{responsive:true,scales:{{y:{{beginAtZero:true,max:100}}}}}}}});

new Chart(document.getElementById('c4'),{{type:'bar',data:{{
  labels:{json.dumps(sink_labels, ensure_ascii=False)},
  datasets:[{{label:'Grok 정확도(%)',data:{json.dumps(sink_grok_acc)},backgroundColor:'#b91c1c',borderRadius:5}}]
  }},options:{{responsive:true,scales:{{y:{{beginAtZero:true,max:100}}}}}}}});
</script>
</body></html>
"""

OUT.write_text(html_doc, encoding="utf-8")
print(f"저장: {OUT}  ({len(html_doc):,} bytes)")
