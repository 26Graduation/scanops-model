"""
OWASP Benchmark(Java) 기반 외부 표준 벤치마크 케이스 샘플링
================================================================
지금까지 ScanOps vs Grok 비교는 전부 우리가 직접 작성한 코드 패턴
(scripts/benchmark_v5_cases.py, scripts/graph_benchmark_cases.py)이었다.
신뢰도를 높이기 위해, 우리가 만들지 않은 **외부 표준 SAST 평가 데이터셋**인
OWASP Benchmark(Java, v1.2, 2740케이스, 11개 카테고리)에서 카테고리별로
균등 샘플링해 동일하게 비교한다.

사전 준비:
  git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git \
    scanops-model/.cache/owasp-benchmark

각 OWASP Benchmark 테스트는 Java 서블릿 전체 파일(doGet/doPost)이며,
실제 취약점/안전 여부는 expectedresults-1.2.csv 에 정답으로 박혀있다
(외부에서 만든 ground truth — 우리가 채점 기준을 만들지 않음).

카테고리(11개) × 10개(true 5 + false 5, 가능한 만큼) = 최대 110케이스.
"""
from __future__ import annotations

import csv
import json
import random
import re
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
OWASP_DIR = BASE / ".cache" / "owasp-benchmark"
CSV_PATH = OWASP_DIR / "expectedresults-1.2.csv"
JAVA_DIR = OWASP_DIR / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
OUT = BASE / "data" / "owasp_benchmark_sample.json"

PER_CATEGORY = 10
SEED = 42

CATEGORY_LABEL = {
    "sqli": "SQL Injection (CWE-89)",
    "weakrand": "Insecure Randomness (CWE-330)",
    "xss": "Cross-Site Scripting (CWE-79)",
    "pathtraver": "Path Traversal (CWE-22)",
    "cmdi": "OS Command Injection (CWE-78)",
    "crypto": "Weak Encryption (CWE-327)",
    "hash": "Weak Hash (CWE-328)",
    "trustbound": "Trust Boundary Violation (CWE-501)",
    "securecookie": "Insecure Cookie (CWE-614)",
    "ldapi": "LDAP Injection (CWE-90)",
    "xpathi": "XPath Injection (CWE-643)",
}


def _extract_method(src: str, name: str) -> str | None:
    """doPost/doGet 메서드 본문을 중괄호 매칭으로 추출."""
    m = re.search(rf"public void {name}\([^)]*\)\s*\n?\s*throws[^{{]*\{{", src)
    if not m:
        m = re.search(rf"public void {name}\([^)]*\)\s*\{{", src)
    if not m:
        return None
    start = m.start()
    depth = 0
    i = src.index("{", m.end() - 1)
    body_start = i
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[start:j + 1]
    return None


def _extract_code(java_path: Path) -> str:
    src = java_path.read_text(encoding="utf-8", errors="ignore")
    for name in ("doPost", "doGet"):
        method = _extract_method(src, name)
        if method and len(method.splitlines()) <= 80:
            return method
    # 폴백: 파일 앞부분 60줄 (import 제외하고 클래스 본문 위주로)
    lines = [l for l in src.splitlines() if not l.strip().startswith(("import ", "package ", "/**", " *", "@author", "@created"))]
    return "\n".join(lines[:60])


def build_cases() -> list[dict]:
    if not CSV_PATH.exists():
        raise FileNotFoundError(
            f"{CSV_PATH} 없음 — 먼저 클론하세요:\n"
            f"  git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git {OWASP_DIR}"
        )
    rows = list(csv.reader(open(CSV_PATH)))[1:]
    by_cat: dict[str, list[tuple]] = {}
    for r in rows:
        if len(r) < 4:
            continue
        test_id, cat, real_vuln, cwe = r[0].strip(), r[1].strip(), r[2].strip(), r[3].strip()
        by_cat.setdefault(cat, []).append((test_id, real_vuln == "true", cwe))

    rng = random.Random(SEED)
    cases: list[dict] = []
    for cat, items in sorted(by_cat.items()):
        trues = [x for x in items if x[1]]
        falses = [x for x in items if not x[1]]
        rng.shuffle(trues); rng.shuffle(falses)
        half = PER_CATEGORY // 2
        picked = trues[:half] + falses[:half]
        rng.shuffle(picked)
        for test_id, is_vuln, cwe in picked:
            java_file = JAVA_DIR / f"{test_id}.java"
            if not java_file.exists():
                continue
            code = _extract_code(java_file)
            cases.append({
                "id": test_id,
                "label": "vuln" if is_vuln else "safe",
                "language": "Java",
                "cwe": f"CWE-{cwe}" if cwe else "-",
                "category": cat,
                "expected_vuln": CATEGORY_LABEL.get(cat, cat) if is_vuln else "SAFE",
                "code": code,
                "source": "OWASP Benchmark v1.2 (external)",
            })
    return cases


CASES = build_cases() if CSV_PATH.exists() else []


if __name__ == "__main__":
    cases = build_cases()
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(cases, indent=2, ensure_ascii=False), encoding="utf-8")
    v = sum(1 for c in cases if c["label"] == "vuln")
    s = len(cases) - v
    print(f"총 {len(cases)}개 | 취약 {v} | 안전 {s}")
    by_cat: dict[str, int] = {}
    for c in cases:
        by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
    for k, n in sorted(by_cat.items()):
        print(f"  {k:14} {n}")
    print(f"저장: {OUT}")
