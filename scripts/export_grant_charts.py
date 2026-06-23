"""
사업지원서 추가자료용 차트 3종 PNG 추출.
generate_business_plan_v5_docx.py의 차트 함수(chart_benchmark, chart_headtohead, chart_market)를
그대로 재사용해 고해상도 PNG로 저장한다.
실행: python scripts/export_grant_charts.py
"""
from pathlib import Path
from generate_business_plan_v5_docx import chart_benchmark, chart_headtohead, chart_market

OUT = Path(__file__).resolve().parents[1] / "reports" / "grant_attachment"
OUT.mkdir(parents=True, exist_ok=True)

charts = {
    "01_benchmark_fpr_vs_grok.png": chart_benchmark,
    "02_grok_missed_cves.png": chart_headtohead,
    "03_tam_sam_som.png": chart_market,
}

for fname, fn in charts.items():
    buf = fn()
    (OUT / fname).write_bytes(buf.getvalue())
    print(f"saved: {OUT / fname}")
