"""
ScanOps 재구축 — CVEfixes 학습 데이터 빌더
==========================================
파이프라인 (노션 설계 그대로):
  CVEfixes 13k 원본 (HuggingFace hitoshura25/cvefixes, streaming)
  ① 언어 필터 (주요 5개: Python / JS·TS / Java / PHP / C·C++)
  ② 각 행을 취약(vulnerable_code) / 안전(fixed_code) 샘플로 전개
  ③ 길이 필터 (min 40자 / max ~4,096토큰 ≈ 12,000자)
  ④ 코드 정규화 해시 dedup (분할 전! 같은 코드가 train/test에 갈라지는 누수 방지)
  ⑤ published_date 최신 10% CVE = test (시간 분할)
  ⑥ 나머지 CVE를 cve_id 그룹 단위로 train/val = 8:1 (전체 80/10/10)

출력: rebuild/data/{train,val,test}.jsonl
  각 줄 = {"prompt", "completion", "meta": {cve_id, language, cwe_id, severity, label, ...}}
  meta는 학습엔 안 쓰이고, 언어별·CWE별 채점 리포트용.

실행:
  .venv/bin/python rebuild/build_dataset.py
"""
from __future__ import annotations

import ast
import hashlib
import json
import random
import re
from collections import Counter
from pathlib import Path

from datasets import load_dataset

SEED = 42
OUT_DIR = Path(__file__).resolve().parent / "data"

# ── ① 언어 필터 ──────────────────────────────────────────────────────────────
# 원본 language 값(소문자화) → 표기 라벨. 여기 없는 언어(Other/Unknown 포함)는 제외.
LANG_MAP = {
    "python": "Python",
    "javascript": "JavaScript", "typescript": "TypeScript",
    "java": "Java",
    "php": "PHP",
    "c": "C", "c++": "C++", "cpp": "C++",
}
# 리포트용 5개 언어 그룹 (JS/TS 묶음, C/C++ 묶음)
LANG_GROUP = {
    "Python": "Python", "JavaScript": "JS/TS", "TypeScript": "JS/TS",
    "Java": "Java", "PHP": "PHP", "C": "C/C++", "C++": "C/C++",
}

# ── ③ 길이 필터 ──────────────────────────────────────────────────────────────
# max 4,096 "토큰"이 목표인데 토크나이저 다운로드 없이 근사: 코드 1토큰 ≈ 3자.
MIN_CHARS, MAX_CHARS = 40, 12_000

# ── 결측 severity 처리: CVSS v3 공식 등급 구간 ───────────────────────────────
def derive_severity(cvss3, severity_raw: str) -> tuple[str, str]:
    """(SEVERITY 등급, CVSS 표기) 도출. cvss3 점수 우선, 없으면 severity 문자열, 둘 다 없으면 UNKNOWN."""
    try:
        score = float(cvss3)
        if 0.0 < score <= 10.0:
            if score >= 9.0:
                return "CRITICAL", f"{score:.1f}"
            if score >= 7.0:
                return "HIGH", f"{score:.1f}"
            if score >= 4.0:
                return "MEDIUM", f"{score:.1f}"
            return "LOW", f"{score:.1f}"
    except (TypeError, ValueError):
        pass
    sev = (severity_raw or "").strip().upper()
    if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return sev, "UNKNOWN"
    return "UNKNOWN", "UNKNOWN"

# ── REASON 추출: 원인 서술 패턴 문장 → 없으면 cwe_description 폴백 ─────────────
CAUSE_PAT = re.compile(
    r"\b(allows?|due to|fails? to|does not (properly|validate|sanitiz|check|verif)"
    r"|improper|lacks?\b|without (proper|validat|sanitiz|check)|leads? to|via\b"
    r"|can be exploited|insufficient)",
    re.I,
)

def _desc_text(cve_description) -> str:
    """cve_description은 [{'lang':'en','value':...}] 리스트(또는 그 문자열화). en value를 꺼낸다."""
    v = cve_description
    if isinstance(v, str) and v.strip().startswith("["):
        try:
            v = ast.literal_eval(v)
        except (ValueError, SyntaxError):
            return v
    if isinstance(v, list):
        for item in v:
            if isinstance(item, dict) and item.get("lang") == "en":
                return str(item.get("value") or "")
        return ""
    return str(v or "")

def extract_reason(cve_description, cwe_description: str) -> str:
    text = re.sub(r"\s+", " ", _desc_text(cve_description)).strip()
    for sent in re.split(r"(?<=[.!?])\s+", text):
        if CAUSE_PAT.search(sent) and 30 <= len(sent) <= 400:
            return sent.strip()
    cwe_desc = re.sub(r"\s+", " ", cwe_description or "").strip()
    if cwe_desc:
        return cwe_desc[:400]
    return ""  # 둘 다 없으면 호출부에서 이 행의 REASON을 생략 판단

# ── 코드 정규화 해시 (dedup 키) ───────────────────────────────────────────────
def code_hash(code: str) -> str:
    normalized = re.sub(r"\s+", " ", code).strip().lower()
    return hashlib.sha1(normalized.encode()).hexdigest()

# ── prompt / completion 템플릿 ────────────────────────────────────────────────
# 프롬프트에 출력 서식을 명시 → 파싱 안정성 + Claude 비교 때 같은 프롬프트로 공정 비교.
PROMPT_TMPL = """Analyze the following {language} code for security vulnerabilities.

```{language}
{code}
```

Respond in exactly this format:
VULNERABILITY: <CWE-id (CWE name)> or NONE
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN> or NONE
CVSS: <score 0.0-10.0> or 0.0
REASON: <one-line explanation> or NONE"""

SAFE_COMPLETION = "VULNERABILITY: NONE\nSEVERITY: NONE\nCVSS: 0.0\nREASON: NONE"

def vuln_completion(cwe_id: str, cwe_name: str, sev: str, cvss: str, reason: str) -> str:
    head = f"{cwe_id.strip()} ({cwe_name.strip()})" if cwe_name.strip() else cwe_id.strip()
    return f"VULNERABILITY: {head}\nSEVERITY: {sev}\nCVSS: {cvss}\nREASON: {reason}"

# ── 메인 ─────────────────────────────────────────────────────────────────────
def main() -> None:
    random.seed(SEED)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("CVEfixes 스트리밍 로드 중… (원본 약 13k 행)")
    ds = load_dataset("hitoshura25/cvefixes", split="train", streaming=True)

    samples: list[dict] = []
    seen_hashes: set[str] = set()
    stats = Counter()

    for row in ds:
        stats["rows_total"] += 1

        # ① 언어 필터
        lang = LANG_MAP.get(str(row.get("language") or "").strip().lower())
        if lang is None:
            stats["drop_language"] += 1
            continue

        cve_id = (row.get("cve_id") or "").strip()
        cwe_id = (row.get("cwe_id") or "").strip()
        # CWE 라벨이 없는 행은 취약 정답을 만들 수 없음 (NVD-CWE-noinfo 등)
        if not cve_id or not cwe_id.startswith("CWE-"):
            stats["drop_no_cwe"] += 1
            continue

        sev, cvss = derive_severity(row.get("cvss3_base_score"), str(row.get("severity") or ""))
        reason = extract_reason(row.get("cve_description"), row.get("cwe_description") or "")
        if not reason:
            reason = f"Vulnerability classified as {cwe_id}."
        pub = (row.get("published_date") or "").strip()

        meta_common = {
            "cve_id": cve_id, "language": lang, "lang_group": LANG_GROUP[lang],
            "cwe_id": cwe_id, "severity": sev, "published_date": pub,
        }

        # ② 취약/안전 쌍 전개 + ③ 길이 필터 + ④ dedup (분할 전, 먼저 본 코드가 이김)
        for code, label in ((row.get("vulnerable_code"), "vuln"), (row.get("fixed_code"), "safe")):
            code = (code or "").strip()
            if not (MIN_CHARS <= len(code) <= MAX_CHARS):
                stats[f"drop_length_{label}"] += 1
                continue
            h = code_hash(code)
            if h in seen_hashes:
                stats["drop_dup"] += 1
                continue
            seen_hashes.add(h)

            completion = (
                vuln_completion(cwe_id, row.get("cwe_name") or "", sev, cvss, reason)
                if label == "vuln" else SAFE_COMPLETION
            )
            samples.append({
                "prompt": PROMPT_TMPL.format(language=lang, code=code),
                "completion": completion,
                "meta": {**meta_common, "label": label},
            })
            stats[f"keep_{label}"] += 1

    # ⑤ 시간 분할: CVE별 published_date 기준 최신 10% CVE = test
    pub_by_cve: dict[str, str] = {}
    for s in samples:
        c = s["meta"]["cve_id"]
        pub_by_cve[c] = max(pub_by_cve.get(c, ""), s["meta"]["published_date"])
    cves_sorted = sorted(pub_by_cve, key=lambda c: pub_by_cve[c])  # 오래된 → 최신
    n_test = max(1, len(cves_sorted) // 10)
    test_cves = set(cves_sorted[-n_test:])

    # ⑥ 나머지 CVE를 그룹 단위로 train/val = 8:1
    rest = [c for c in cves_sorted if c not in test_cves]
    random.shuffle(rest)
    n_val = max(1, len(rest) // 9)
    val_cves = set(rest[:n_val])

    splits: dict[str, list[dict]] = {"train": [], "val": [], "test": []}
    for s in samples:
        c = s["meta"]["cve_id"]
        splits["test" if c in test_cves else "val" if c in val_cves else "train"].append(s)

    # 저장 + 리포트
    for name, items in splits.items():
        path = OUT_DIR / f"{name}.jsonl"
        with path.open("w") as f:
            for s in items:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        print(f"\n=== {name}: {len(items)}건 → {path}")
        print("  라벨:", dict(Counter(s["meta"]["label"] for s in items)))
        print("  언어:", dict(Counter(s["meta"]["lang_group"] for s in items)))
        top_cwe = Counter(s["meta"]["cwe_id"] for s in items if s["meta"]["label"] == "vuln")
        print("  CWE top5:", top_cwe.most_common(5))

    test_dates = sorted(pub_by_cve[c] for c in test_cves)
    print(f"\ntest 기간: {test_dates[0][:10]} ~ {test_dates[-1][:10]} (CVE {len(test_cves)}개)")
    print(f"train/val/test CVE 수: {len(rest) - n_val}/{n_val}/{n_test}")
    print("\n필터 통계:", dict(stats))

if __name__ == "__main__":
    main()
