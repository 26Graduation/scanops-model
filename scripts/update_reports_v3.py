"""벤치마크 결과를 보고서와 노션 문서에 자동으로 채워 넣는 스크립트.

benchmark_v3.py 실행 후 사용:
  python scripts/update_reports_v3.py
"""

from __future__ import annotations

import json
from pathlib import Path

REPORTS = Path(__file__).resolve().parents[1] / "reports"
V2_JSON = REPORTS / "results_ScanOps_v2_QLoRAplusRAG_Adaptive.json"
V3_JSON = REPORTS / "results_ScanOps_v3_QLoRAplusRAG_Adaptive.json"
REPORT_MD = REPORTS / "ScanOps_Final_Report_v3.md"
NOTION_MD = REPORTS / "notion_tech_stack_v3.md"


def load_results() -> tuple[dict, dict]:
    v2 = json.loads(V2_JSON.read_text()) if V2_JSON.exists() else {}
    v3 = json.loads(V3_JSON.read_text()) if V3_JSON.exists() else {}
    return v2, v3


def build_case_table(v2: dict, v3: dict) -> str:
    v2_map = {r["id"]: r for r in v2.get("results", [])}
    v3_map = {r["id"]: r for r in v3.get("results", [])}

    lines = [
        "```",
        f"{'ID':<4}{'언어':<26}{'취약점':<40}{'v2':>4}{'v3':>4}{'Stage':>6}",
        "─" * 84,
    ]

    for id_ in range(1, 21):
        r2 = v2_map.get(id_, {})
        r3 = v3_map.get(id_, {})
        lang = r3.get("language", r2.get("language", "?"))[:24]
        vuln = r3.get("expected_vuln", r2.get("expected_vuln", "?"))[:38]
        t2 = "✓" if r2.get("detected") else "✗"
        t3 = "✓" if r3.get("detected") else "✗"
        stage = r3.get("stage", "?")
        lines.append(f"{id_:<4}{lang:<26}{vuln:<40}{t2:>4}{t3:>4}{stage:>6}")

    lines.append("─" * 84)
    lines.append(
        f"{'합계':<30}{'':<40}"
        f"{v2.get('detected', '?'):>4}/{v2.get('total', 20)}"
        f"{v3.get('detected', '?'):>4}/{v3.get('total', 20)}"
    )
    lines.append(
        f"{'탐지율':<30}{'':<40}"
        f"{v2.get('detect_pct', '?'):>5}%"
        f"{v3.get('detect_pct', '?'):>5}%"
    )
    lines.append("```")
    return "\n".join(lines)


def build_stage_chart(v3: dict) -> str:
    n1 = v3.get("stage1_count", 0)
    n2 = v3.get("stage2_count", 0)
    nm = 20 - v3.get("detected", 0)
    total = 20
    bar1 = "█" * round(n1 / total * 20)
    bar2 = "█" * round(n2 / total * 20)
    bar3 = "█" * round(nm / total * 20)
    return (
        "```\n"
        f"Stage 1 (QLoRA 직접 탐지)  {bar1:<20} {n1}건 ({n1/total*100:.0f}%)\n"
        f"Stage 2 (Base+RAG 폴백)    {bar2:<20} {n2}건 ({n2/total*100:.0f}%)\n"
        f"미탐지                      {bar3:<20} {nm}건 ({nm/total*100:.0f}%)\n"
        "```"
    )


def patch_file(path: Path, replacements: list[tuple[str, str]]) -> None:
    text = path.read_text(encoding="utf-8")
    for old, new in replacements:
        if old in text:
            text = text.replace(old, new)
            print(f"  패치 완료: {repr(old[:40])} → {repr(new[:40])}")
        else:
            print(f"  패치 대상 없음 (이미 수정됨?): {repr(old[:40])}")
    path.write_text(text, encoding="utf-8")


def main() -> None:
    if not V3_JSON.exists():
        print("v3 벤치마크 결과 없음. 먼저 benchmark_v3.py를 실행하세요.")
        return

    v2, v3 = load_results()

    print("=" * 60)
    print("  보고서 업데이트")
    print("=" * 60)
    print(f"  v2: {v2.get('detect_pct')}% ({v2.get('detected')}/20)  {v2.get('avg_time')}s")
    print(f"  v3: {v3.get('detect_pct')}% ({v3.get('detected')}/20)  {v3.get('avg_time')}s")
    print()

    pct3     = v3.get("detect_pct", "TBD")
    det3     = v3.get("detected", "TBD")
    time3    = v3.get("avg_time", "TBD")
    stage1_3 = v3.get("stage1_count", "?")
    stage2_3 = v3.get("stage2_count", "?")

    pct_diff  = round(float(pct3) - float(v2.get("detect_pct", 0)), 1) if pct3 != "TBD" else "?"
    time_diff = round(float(time3) - float(v2.get("avg_time", 0)), 2) if time3 != "TBD" else "?"

    case_table = build_case_table(v2, v3)
    stage_chart = build_stage_chart(v3)

    # ── 최종 보고서 업데이트 ──────────────────────────────────────
    report_patches = [
        ("ScanOps v3 (QLoRA+RAG Adaptive)    █████████░  ??%  ??/20  ??s ← 현재",
         f"ScanOps v3 (QLoRA+RAG Adaptive)    {'█'*round(float(pct3)/10) if pct3!='TBD' else '??'}{'░'*(10-round(float(pct3)/10)) if pct3!='TBD' else ''}  {pct3}%  {det3}/20  {time3}s ← 현재"),

        ("| **탐지율** | 95% (19/20) | TBD | - |",
         f"| **탐지율** | 95% (19/20) | {pct3}% ({det3}/20) | {'+' if pct_diff >= 0 else ''}{pct_diff}% |"),

        ("| **평균 응답** | 2.71s | TBD | - |",
         f"| **평균 응답** | 2.71s | {time3}s | {'+' if time_diff >= 0 else ''}{time_diff}s |"),

        ("| **Stage1 비율** | 75% | TBD | - |",
         f"| **Stage1 비율** | 75% | {round(stage1_3/20*100)}% | - |"),
    ]
    print(f"\n[1/2] {REPORT_MD.name} 패치 중...")
    patch_file(REPORT_MD, report_patches)

    # ── 노션 문서 업데이트 ──────────────────────────────────────
    notion_patches = [
        ("v3: [벤치마크 실행 후 업데이트 예정]",
         f"v3: {det3}/20 = {pct3}%  (Stage1: {stage1_3}건  Stage2: {stage2_3}건  avg {time3}s)"),
    ]
    print(f"\n[2/2] {NOTION_MD.name} 패치 중...")
    patch_file(NOTION_MD, notion_patches)

    print("\n완료! 보고서 업데이트됨.")
    print(f"  탐지율 변화: 95% → {pct3}% ({'+' if pct_diff >= 0 else ''}{pct_diff}%)")
    print(f"  응답 시간:   2.71s → {time3}s")


if __name__ == "__main__":
    main()
