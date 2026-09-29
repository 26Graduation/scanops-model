"""
ScanOps v3 — 최종 표 조립기
============================
out/ 에 흩어진 report/sweep/ensemble json을 한 표로 모은다.
숫자를 손으로 옮기다 틀리는 걸 막으려고 스크립트로 만든다.

실행: python rebuild/make_results.py > out/v3_tables.md
"""
from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "out"


def jload(name: str):
    p = OUT / name
    return json.loads(p.read_text()) if p.exists() else None


def row(label: str, s: dict | None, extra: str = "") -> str:
    if not s:
        return f"| {label} | — | — | — | — | {extra} |"
    return (f"| {label} | {s.get('f1', 0):.3f} | {s.get('recall', 0):.3f} | "
            f"{s.get('fpr', 0):.3f} | {s.get('precision', 0):.3f} | {extra} |")


def section(title: str) -> None:
    print(f"\n### {title}\n")
    print("| 시스템·운영점 | F1 | recall | FPR | precision | 비고 |")
    print("|---|---|---|---|---|---|")


def main() -> None:
    print("# v3 결과 표 (자동 생성)")

    # ── 내부 test ────────────────────────────────────────────────────────────
    section("내부 test (1,197건) — 목표: F1 > 0.805 AND FPR < 0.157")
    v1 = jload("test_report.json")
    print(row("ScanOps v1 (greedy)", v1 and v1["overall"], "기존 최고"))
    v2 = jload("v2_internal_report.json")
    print(row("ScanOps v2 (greedy)", v2 and v2["overall"], "데이터확장 실패판"))
    for tag in ("v3s42", "v3s1337"):
        r = jload(f"{tag}_test_report.json")
        print(row(f"{tag} (greedy)", r and r["overall"], "생성 기반"))
        sw = jload(f"{tag}_sweep_test.json")
        if sw:
            print(row(f"{tag} (logprob τ, val선정)", sw.get("report"),
                      f"AUC {sw.get('auc_report')}"))

    # ── 외부 벤치 ────────────────────────────────────────────────────────────
    for base, target, claude in (("primevul", 0.633, "F1 0.633 / R 0.844 / FPR 0.822"),
                                 ("cleanvul_v2", 0.640, "F1 0.640 / R 0.845 / FPR 0.796")):
        section(f"{base} report split — 목표: F1 > {target} (Claude: {claude})")
        for tag in ("v1", "v3s42", "v3s1337"):
            sw = jload(f"{tag}_sweep_{base}.json")
            if not sw:
                continue
            print(row(f"{tag} logprob τ(F1최대)", sw.get("report"),
                      f"AUC {sw.get('auc_report')} — FPR 확인 필요"))
            print(row(f"{tag} logprob τ(FPR≤0.35)", sw.get("capped_fpr35_report"), "운영 가능 점"))
            g = jload(f"{tag}_{base}_report_report.json")
            if g:
                print(row(f"{tag} greedy", g["overall"], "생성 기반"))
            tb = sw.get("trivial_all_vuln_report")
            if tb:
                print(row("(자명) 무조건 VULNERABLE", tb, "균형셋의 공짜 F1"))
        v = jload(f"v3s42_votes_sweep_{base}.json")
        if v:
            print(row("v3s42 self-consistency k=5", v.get("report_at_t_capped"),
                      f"t={v.get('chosen_t_capped')}"))
        e = jload(f"ensemble_{base}_v3s42_v1.json")
        if e:
            print(row("앙상블 v3s42+v1 (점수합)", e["report"].get("at_tau_capped"),
                      f"AUC {e['report'].get('auc')} w={e['chosen']['w']}"))

    # ── 비용 ─────────────────────────────────────────────────────────────────
    print("\n### 추론 비용 (성능-비용 파레토)\n")
    print("| 기법 | 케이스당 샘플 | 케이스당 초 | 상대 비용 |")
    print("|---|---|---|---|")
    base_cost = None
    for tag, name, label in (("v3s42", "test", "greedy (4줄 생성)"),
                             ("v3s42", "primevul_report", "greedy (4줄 생성)")):
        r = jload(f"{tag}_{name}_report.json")
        if r and "cost" in r:
            c = r["cost"]
            base_cost = base_cost or c["secs_per_case"]
            print(f"| {label} / {name} | {c['samples_per_case']} | {c['secs_per_case']} | "
                  f"{c['secs_per_case']/base_cost:.1f}× |")
    for name in ("primevul_report", "cleanvul_v2_tune"):
        r = jload(f"v3s42_{name}_votes_k5_report.json")
        if r and "cost" in r:
            c = r["cost"]
            print(f"| self-consistency k=5 / {name} | {c['samples_per_case']} | "
                  f"{c['secs_per_case']} | {c['secs_per_case']/(base_cost or 1):.1f}× |")
    print("| logprob 1회 forward | 0 (생성 없음) | 0.18 | 기준 대비 매우 쌈 |")


if __name__ == "__main__":
    main()
