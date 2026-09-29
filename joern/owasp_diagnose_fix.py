"""Phase 3-b — 진단셋(55건)에서 Joern v4 가 놓친 방어 구문을 분류한다.

홀드아웃은 건드리지 않는다. 여기서 본 것만으로 sanitizers.json 을 고친다.

  python joern/owasp_diagnose_fix.py            # Joern 실행 + 분류
  python joern/owasp_diagnose_fix.py --analyze  # 저장된 결과로 분류만

출력: rebuild/out/owasp_diag_v4_fix.jsonl / owasp_diag_report_fix.json
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["JOERN_SCRIPT"] = str(ROOT / "joern" / "queries" / "taint_v4.sc")

from joern.handler_joern import SCRIPT as _ACTIVE, analyze_batch  # noqa: E402
from joern.langmap import resolve  # noqa: E402
from joern.owasp_split_fix import category_of  # noqa: E402
from joern.sanitizer_spec import write_san_file  # noqa: E402

if Path(_ACTIVE).name != "taint_v4.sc":
    raise SystemExit(f"FATAL: 활성 쿼리가 v4 가 아니다 → {_ACTIVE}")

OUT = ROOT / "rebuild" / "out"

# 놓친 방어 구문 분류 — OWASP 특정 문자열이 아니라 **일반 API 이름**으로만 본다.
DEFENSE = [
    ("param_binding", re.compile(
        r"\.set(String|Int|Long|Double|Boolean|Object|Date|Timestamp)\s*\(|"
        r"prepareStatement\s*\(|PreparedStatement|createQuery\([^)]*setParameter", re.I)),
    ("output_encoder", re.compile(
        r"ESAPI\s*\.\s*encoder\(\)|encodeFor(HTML|JavaScript|URL|CSS|XML|SQL)|"
        r"StringEscapeUtils|escapeHtml|htmlEscape|HtmlUtils\.htmlEscape|"
        r"URLEncoder\.encode|Encode\.for", re.I)),
    ("allowlist_check", re.compile(
        r"\b(equals|equalsIgnoreCase)\s*\(\s*\"|switch\s*\(|"
        r"allowlist|whitelist|ALLOWED|in_array|\.contains\s*\(", re.I)),
    ("type_conversion", re.compile(
        r"Integer\.parseInt|Long\.parseLong|Double\.parseDouble|Float\.parseFloat|"
        r"Boolean\.parseBoolean|UUID\.fromString", re.I)),
    ("path_canonical", re.compile(
        r"getCanonicalPath|getCanonicalFile|toRealPath|\.normalize\s*\(|"
        r"FilenameUtils\.getName", re.I)),
    ("regex_validate", re.compile(
        r"Pattern\.(compile|matches)|\.matches\s*\(\s*\"|matcher\s*\(", re.I)),
]


def classify(code: str) -> list[str]:
    return [name for name, rx in DEFENSE if rx.search(code)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--analyze", action="store_true")
    args = ap.parse_args()

    rows = [json.loads(l) for l in (ROOT / "data" / "owasp_holdout_bench.jsonl").open()]
    split = json.loads((OUT / "owasp_split_fix.json").read_text())
    diag_idx = split["diagnostic"]
    cases = [(f"owaspd_{i}", rows[i]) for i in diag_idx]
    print(f"[diag] 진단셋 {len(cases)}건 (홀드아웃 {len(split['holdout'])}건은 열지 않는다)",
          flush=True)

    out_path = OUT / "owasp_diag_v4_fix.jsonl"
    done: dict[str, dict] = {}
    if out_path.exists():
        for line in out_path.open():
            try:
                o = json.loads(line)
                done[o["case_id"]] = o
            except Exception:  # noqa: BLE001
                pass

    if not args.analyze:
        lang = rows[0]["language"]
        jl = resolve(lang)[1]
        san_dir = Path(os.getenv("TMPDIR", "/tmp")) / "scanops_fix_san"
        san_dir.mkdir(parents=True, exist_ok=True)
        p = san_dir / f"{jl}.txt"
        n = write_san_file(jl, p)
        os.environ["JOERN_SANITIZER_FILE"] = str(p)
        print(f"[diag] sanFile {jl}: {n} patterns", flush=True)

        todo = [(cid, r) for cid, r in cases if cid not in done]
        t0 = time.time()
        with out_path.open("a") as fh:
            for i in range(0, len(todo), 25):
                batch = todo[i:i + 25]
                res = analyze_batch(f"diag_{i}_{int(time.time())}", lang,
                                    [{"path": cid, "content": r["code"]} for cid, r in batch],
                                    chunk_size=25)
                for cid, r in batch:
                    v = res["results"].get(cid, {})
                    rec = {"case_id": cid, "label": r["label"], "cat": category_of(r["code"]),
                           "joern_verdict": v.get("verdict", "unknown"),
                           "categories": v.get("categories", []),
                           "sanitized_categories": v.get("sanitized_categories", []),
                           "defenses": classify(r["code"])}
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    done[cid] = rec
                fh.flush()
                print(f"[diag] {i+len(batch)}/{len(todo)} {(time.time()-t0)/60:.1f}분", flush=True)

    recs = [done[cid] for cid, _ in cases if cid in done]
    fp = [r for r in recs if r["joern_verdict"] == "vuln" and r["label"] == "safe"]
    tp = [r for r in recs if r["joern_verdict"] == "vuln" and r["label"] == "vuln"]

    report = {
        "n_diag": len(recs),
        "verdict_dist": dict(collections.Counter(r["joern_verdict"] for r in recs)),
        "false_positives": len(fp), "true_positives": len(tp),
        "fp_defense_types": dict(collections.Counter(
            d for r in fp for d in (r["defenses"] or ["(감지된 방어 없음)"]))),
        "fp_by_category": dict(collections.Counter(r["cat"] for r in fp)),
        "tp_by_category": dict(collections.Counter(r["cat"] for r in tp)),
        "fp_no_defense": sum(1 for r in fp if not r["defenses"]),
    }
    (OUT / "owasp_diag_report_fix.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False))
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
