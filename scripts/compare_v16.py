"""V16 vs V15(재구성) vs v13 vs v14 vs Grok — 4벤치 종합 비교
================================================================
V15는 재학습 없는 앙상블이므로 저장된 per-case 예측(results_v13/v14_*.json)의
OR(v13_llm ∨ v14_llm ∨ graph=='vuln')로 재구성한다. 케이스 순서는 벤치 jsonl
순회 순서라 세 파일 모두 동일(자가검증: label 시퀀스 일치 확인).

실행: python scripts/compare_v16.py
산출: reports/V16_RESULTS.md
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
BENCHES = ["cvefixes_benchmark", "owasp_method_bench",
           "cybernative_benchmark", "diversevul_benchmark"]
NAMES = {"cvefixes_benchmark": "CVEfixes 157 (실제 CVE·출처동일 CVE분리)",
         "owasp_method_bench": "OWASP 110 (완전 zero-shot)",
         "cybernative_benchmark": "CyberNative 154 (출처동일 해시분리)",
         "diversevul_benchmark": "DiverseVul 150 (완전 독립출처)"}


def metrics(rows, flags):
    tp = sum(1 for r, f in zip(rows, flags) if r["label"] == "vuln" and f)
    fn = sum(1 for r, f in zip(rows, flags) if r["label"] == "vuln" and not f)
    fp = sum(1 for r, f in zip(rows, flags) if r["label"] == "safe" and f)
    tn = sum(1 for r, f in zip(rows, flags) if r["label"] == "safe" and not f)
    rec = tp / (tp + fn) * 100 if tp + fn else 0
    fpr = fp / (fp + tn) * 100 if fp + tn else 0
    prec = tp / (tp + fp) * 100 if tp + fp else 0
    acc = (tp + tn) / (len(rows)) * 100 if rows else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    return {"f1": round(f1, 1), "recall": round(rec, 1), "fpr": round(fpr, 1),
            "precision": round(prec, 1), "accuracy": round(acc, 1)}


def load(tag, bench):
    p = BASE / "reports" / f"results_{tag}_{bench}.json"
    return json.load(open(p)) if p.exists() else None


def main():
    lines = ["# V16 4벤치 결과 — v13/v14/V15/Grok 비교\n"]
    agg = {}  # sys -> list of metric dicts

    for bench in BENCHES:
        d16, d13, d14 = load("v16", bench), load("v13", bench), load("v14", bench)
        if not d16:
            print(f"({bench}: v16 결과 없음 — 스킵)")
            continue
        rows16 = d16["cases"]
        systems = {}
        systems["v16 LLM"] = [r["llm"] for r in rows16]
        systems["v16+그래프"] = [r["hybrid"] for r in rows16]
        if d13 and d14:
            r13, r14 = d13["cases"], d14["cases"]
            if [r["label"] for r in r13] == [r["label"] for r in r14] == [r["label"] for r in rows16]:
                systems["v13+그래프"] = [r["hybrid"] for r in r13]
                systems["v14+그래프"] = [r["hybrid"] for r in r14]
                systems["V15 앙상블"] = [a["llm"] or b["llm"] or a["graph"] == "vuln"
                                         for a, b in zip(r13, r14)]
            else:
                print(f"({bench}: 케이스 순서 불일치 — v13/v14/V15 스킵)")
        grok = (d13 or {}).get("grok")

        lines.append(f"\n## {NAMES[bench]}\n")
        lines.append("| 시스템 | F1 | 재현율 | 오탐률 | 정밀도 | 정확도 |")
        lines.append("|---|---|---|---|---|---|")
        for name, flags in systems.items():
            m = metrics(rows16, flags)
            agg.setdefault(name, []).append(m)
            lines.append(f"| {name} | {m['f1']} | {m['recall']}% | {m['fpr']}% | "
                         f"{m['precision']}% | {m['accuracy']}% |")
        if grok:
            agg.setdefault("Grok", []).append(grok)
            lines.append(f"| Grok (저장치) | {grok['f1']} | {grok['recall']}% | "
                         f"{grok['fpr']}% | {grok['precision']}% | {grok['accuracy']}% |")

    lines.append("\n## 4벤치 평균\n")
    lines.append("| 시스템 | F1 | 재현율 | 오탐률 | 정확도 |")
    lines.append("|---|---|---|---|---|")
    for name, ms in agg.items():
        avg = {k: round(sum(m[k] for m in ms) / len(ms), 1)
               for k in ("f1", "recall", "fpr", "accuracy")}
        lines.append(f"| {name} (n={len(ms)}) | {avg['f1']} | {avg['recall']}% | "
                     f"{avg['fpr']}% | {avg['accuracy']}% |")

    out = BASE / "reports" / "V16_RESULTS.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\n저장: {out}")


if __name__ == "__main__":
    main()
