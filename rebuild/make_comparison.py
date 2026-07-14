"""
ScanOps 재구축 — 정답 대조표 생성 (벤치마크당 1개 CSV)
========================================================
"이 코드의 정답은 이건데, 우리 모델은 뭐라 했고 Claude는 뭐라 했나"를
한 줄씩 나란히 볼 수 있는 파일을 만든다. 엑셀/Numbers로 바로 열림.

대상 3개:
  internal  — data/test.jsonl        + out/test_predictions.jsonl        + out/compare_claude_predictions.jsonl
  primevul  — data/primevul_test.jsonl + out/external_primevul_predictions.jsonl + out/compare_claude_primevul_predictions.jsonl
  cleanvul  — data/cleanvul_test.jsonl + out/external_cleanvul_predictions.jsonl + out/compare_claude_cleanvul_predictions.jsonl

모든 예측 파일은 데이터 파일과 같은 행 순서로 기록돼 있음(각 스크립트가 순서대로 순회).
안전장치로 행마다 meta(cve_id/pair_id)가 일치하는지 검증한다.

컬럼: 위치정보(pair_id/cve/commit) · 언어 · 정답 · 우리답(라벨/CWE/사유) · Claude답(〃)
      · 맞았는지(ours_correct/claude_correct). 코드 원문은 용량 문제로 제외 —
      코드는 data/*.jsonl의 같은 행(row 컬럼 번호)에서 확인.

실행: .venv/bin/python rebuild/make_comparison.py  →  out/comparison_{internal,primevul,cleanvul}.csv
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"

TARGETS = {
    "internal": ("data/test.jsonl", "out/test_predictions.jsonl", "out/compare_claude_predictions.jsonl"),
    "primevul": ("data/primevul_test.jsonl", "out/external_primevul_predictions.jsonl", "out/compare_claude_primevul_predictions.jsonl"),
    "cleanvul": ("data/cleanvul_test.jsonl", "out/external_cleanvul_predictions.jsonl", "out/compare_claude_cleanvul_predictions.jsonl"),
}


def jl(rel: str) -> list[dict]:
    return [json.loads(l) for l in (ROOT / rel).open()]


def reason_of(raw: str) -> str:
    """모델의 4줄 출력에서 REASON 줄만 추출 (대조표 가독용, 200자 컷)."""
    for line in (raw or "").splitlines():
        if line.strip().upper().startswith("REASON:"):
            return line.split(":", 1)[1].strip()[:200]
    return ""


def main() -> None:
    for name, (data_p, ours_p, claude_p) in TARGETS.items():
        rows, ours, claude = jl(data_p), jl(ours_p), jl(claude_p)
        assert len(rows) == len(ours) == len(claude), f"{name}: 행 수 불일치"

        out_path = OUT / f"comparison_{name}.csv"
        with out_path.open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["row", "pair_id", "cve_id", "cwe_id(정답)", "commit/출처", "language",
                        "정답", "우리_판정", "우리_CWE", "우리_정답여부", "우리_사유",
                        "Claude_판정", "Claude_CWE", "Claude_정답여부", "Claude_사유"])
            for i, (r, o, c) in enumerate(zip(rows, ours, claude)):
                m = r["meta"]
                # 순서 안전장치: 세 파일이 같은 샘플을 가리키는지 확인
                assert o["meta"]["cve_id"] == m["cve_id"] == c["meta"]["cve_id"], f"{name} {i}행 불일치"
                src = m.get("commit_id") or m.get("commit_url") or m.get("published_date") or ""
                w.writerow([
                    i, m.get("pair_id", ""), m["cve_id"], m.get("cwe_id", ""), src, m["language"],
                    m["label"],
                    o["label"], o.get("cwe", ""), "O" if o["label"] == m["label"] else "X", reason_of(o.get("raw", "")),
                    c["label"], c.get("cwe", ""), "O" if c["label"] == m["label"] else "X", reason_of(c.get("raw", "")),
                ])
        print(f"{name}: {len(rows)}행 → {out_path}")


if __name__ == "__main__":
    main()
