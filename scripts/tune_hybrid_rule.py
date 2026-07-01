"""V14 하이브리드 결합규칙 튜닝 — 재학습 없이 3벤치에서 최적 규칙 탐색.
================================================================
관찰(V13): 현재 규칙(graph vuln→VULN, strong-safe→veto, else LLM)은
  - OWASP(LLM 약함): 그래프가 재현율 보강 → 도움.
  - CyberNative(LLM 강함): 그래프 'vuln'이 오탐 추가 + 'safe' veto가 정탐 제거 → 해.
→ 그래프를 "항상 적용"하지 말고, **재현율만 보강하고 LLM 양성을 덮지 않는** 적응적 규칙이 나을 수 있다.

각 케이스의 (llm, grok, label)은 저장된 결과 JSON에서, (graph verdict, strong)은 코드에서
재유도(규칙기반·LLM 불필요)해 여러 결합규칙을 시뮬레이션한다.

실행: python scripts/tune_hybrid_rule.py
"""
from __future__ import annotations
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from scanops.core.multi_graph import analyze as analyze_code

BENCHES = [
    ("CVEfixes",   "data/cvefixes_benchmark.jsonl",   "reports/results_v12_cvefixes_benchmark.json"),
    ("OWASP",      "data/owasp_method_bench.jsonl",    "reports/results_v12_owasp_method_bench.json"),
    ("CyberNative","data/cybernative_benchmark.jsonl", "reports/results_v12_cybernative_benchmark.json"),
]

def _metrics(rows, key):
    tp=sum(1 for r in rows if r["label"]=="vuln" and r[key]); fn=sum(1 for r in rows if r["label"]=="vuln" and not r[key])
    fp=sum(1 for r in rows if r["label"]=="safe" and r[key]); tn=sum(1 for r in rows if r["label"]=="safe" and not r[key])
    P=tp/(tp+fp) if tp+fp else 0; R=tp/(tp+fn) if tp+fn else 0
    return dict(f1=round(2*P*R/(P+R)*100,1) if P+R else 0, rec=round(R*100,1),
                fpr=round(fp/(fp+tn)*100,1) if fp+tn else 0, acc=round((tp+tn)/len(rows)*100,1))

# ── 결합규칙들 (각 케이스: llm bool, gv verdict, strong bool) ──────────────────
def R0_llm(llm, gv, strong):      return llm
def R1_current(llm, gv, strong):  # 현행
    if gv=="vuln": return True
    if gv=="safe" and strong: return False
    return llm
def R2_recall_only(llm, gv, strong):  # 그래프는 재현율만 보강, LLM 양성은 절대 안 덮음
    if llm: return True
    if gv=="vuln": return True       # LLM이 놓친 것만 그래프가 보강
    return False
def R3_strongsafe_veto(llm, gv, strong):  # LLM 우선 + strong-safe만 veto
    if gv=="safe" and strong: return False
    return llm
def R4_recall_plus_strongveto(llm, gv, strong):  # R2 + strong-safe veto
    if gv=="safe" and strong: return False
    if llm: return True
    if gv=="vuln": return True
    return False

RULES = [("LLM단독",R0_llm),("현행(R1)",R1_current),("재현보강(R2)",R2_recall_only),
         ("strong-veto(R3)",R3_strongsafe_veto),("R2+veto(R4)",R4_recall_plus_strongveto)]

def main():
    # 케이스별 graph verdict+strong 재유도
    per_bench = {}
    for name, bench_path, res_path in BENCHES:
        cases_meta = [json.loads(l) for l in open(ROOT/bench_path) if l.strip()]
        res = json.load(open(ROOT/res_path))["cases"]
        rows = []
        for meta, rc in zip(cases_meta, res):
            g = analyze_code(meta["code"], meta["language"])
            rows.append({"label": rc["label"], "llm": rc["llm"], "grok": rc.get("grok"),
                         "gv": g["verdict"], "strong": bool(g.get("strong"))})
        per_bench[name] = rows

    for name, rows in per_bench.items():
        print(f"\n{'='*78}\n{name} ({len(rows)}케이스)\n{'='*78}")
        print(f"{'규칙':18} {'F1':>6} {'재현율':>7} {'오탐률':>7} {'정확도':>7}")
        for rname, fn in RULES:
            for r in rows: r["_h"]=fn(r["llm"], r["gv"], r["strong"])
            m=_metrics(rows,"_h")
            print(f"{rname:18} {m['f1']:>6} {m['rec']:>6}% {m['fpr']:>6}% {m['acc']:>6}%")
        if rows[0]["grok"] is not None:
            m=_metrics(rows,"grok")
            print(f"{'Grok':18} {m['f1']:>6} {m['rec']:>6}% {m['fpr']:>6}% {m['acc']:>6}%")

if __name__ == "__main__":
    main()
