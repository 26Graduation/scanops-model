"""
언어별 AUC 분해 — "학습 언어 분포 재조정"이 다음 레버로 타당한지 직접 검정
========================================================================
`FINAL_ARCHITECTURE_REPORT.md` §7 의 다음 레버 후보 중 하나는
"학습 데이터의 C/C++ 67% 편중을 재조정한다"였다. 그 레버가 성립하려면
**학습 비중이 낮은 언어에서 성능이 낮아야** 한다. 그것을 직접 잰다.

비용 $0 — 기존 logprob 산출물만 읽는다.
실행: python3 rebuild/lang_breakdown.py [tag]
출력: out/lang_breakdown_{tag}.json
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from sweep_threshold import auc  # noqa: E402

TAG = sys.argv[1] if len(sys.argv) > 1 else "v1"
SPLITS = ["test", "cleanvul_v2_report", "primevul_report", "cvefixes157", "cybernative154"]
MIN_N = 40   # 이보다 작은 언어 셀은 AUC 를 보고하되 "표본 부족"으로 표시


def main() -> None:
    train = [json.loads(l) for l in (ROOT / "data" / "train_v3.jsonl").open()]
    share = Counter(r["meta"].get("lang_group") for r in train)
    n_tr = sum(share.values())
    train_share = {k: round(v / n_tr, 4) for k, v in share.items()}

    out = {"tag": TAG, "train_lang_share": train_share, "train_n": n_tr, "splits": {}}
    for sp in SPLITS:
        p = ROOT / "out" / f"{TAG}_logprob_{sp}.jsonl"
        if not p.exists():
            out["splits"][sp] = {"status": "미실행"}
            continue
        recs = [json.loads(l) for l in p.open()]
        g = defaultdict(list)
        for r in recs:
            g[r["meta"].get("lang_group", "?")].append(r)
        rows = []
        for k, v in sorted(g.items(), key=lambda x: -len(x[1])):
            rows.append({
                "lang": k, "n": len(v),
                "n_vuln": sum(1 for r in v if r["meta"]["label"] == "vuln"),
                "auc": auc(v),
                "train_share": train_share.get(k),
                "small_sample": len(v) < MIN_N,
            })
        out["splits"][sp] = {"overall_auc": auc(recs), "by_lang": rows}

    p = ROOT / "out" / f"lang_breakdown_{TAG}.json"
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    for sp, e in out["splits"].items():
        if "by_lang" not in e:
            continue
        print(f"{sp} (전체 {e['overall_auc']})")
        for r in e["by_lang"]:
            ts = f"{r['train_share']:.1%}" if r["train_share"] is not None else "학습분포에 없음"
            flag = " *표본부족" if r["small_sample"] else ""
            print(f"   {r['lang']:20s} n={r['n']:5d}  AUC={r['auc']:.4f}  학습비중 {ts}{flag}")
    print(f"→ {p}")


if __name__ == "__main__":
    main()
