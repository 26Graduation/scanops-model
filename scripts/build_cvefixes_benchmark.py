"""
CVEfixes held-out 벤치마크 빌더 (V12 2번째 외부 평가셋)
================================================================
출처: HuggingFace `hitoshura25/cvefixes` — 실제 CVE의 패치 커밋에서 추출한
      (vulnerable_code, fixed_code) 다언어 쌍. published_date·cwe·언어 포함.

목적: OWASP 외에 **두 번째 독립 벤치마크**로 과적합을 반증한다.
  - vulnerable_code → label=vuln,  fixed_code → label=safe (패치 후 = 안전)
  - **2024년 이후 CVE만** → 범용 LLM(Grok) 학습 컷오프 이후 → 우리 RAG/최신성 강점
  - 우리 시스템 대상 언어로 한정 (그래프가 커버하는 언어 + C/C++)

과적합 차단:
  - 학습셋(lora_train_v12_clean)과 코드 해시 dedup → 누수 0 보장.
  - 같은 코드(vuln/fixed 동일) 중복 제거.

실행:  python scripts/build_cvefixes_benchmark.py --n 160
산출:  data/cvefixes_benchmark.jsonl  ({language, code, label, cwe, cve, severity, published})
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# 우리 시스템이 다루는 언어 → 표준 라벨 정규화
LANG_MAP = {
    "python": "Python", "javascript": "Node.js / Express", "typescript": "TypeScript",
    "java": "Java", "go": "Go", "php": "PHP", "c#": "C#", "csharp": "C#",
    "ruby": "Ruby", "c": "C", "c++": "C++", "cpp": "C++",
}
MIN_LEN, MAX_LEN = 40, 1600      # 너무 짧거나(노이즈) 긴(컨텍스트 초과) 코드 제외
MIN_YEAR = 2024                  # Grok 학습 컷오프 이후

def _norm(c: str) -> str: return re.sub(r"\s+", " ", c or "").strip().lower()
def _h(c: str) -> str: return hashlib.sha1(_norm(c).encode()).hexdigest()

def _train_hashes() -> set[str]:
    ex = set()
    for name in ("lora_train_v12_clean.jsonl", "lora_train_v12_clean_val.jsonl"):
        p = ROOT / "data" / name
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            m = re.search(r"```[a-zA-Z+#./]*\n(.*?)```", json.loads(line)["prompt"], re.S)
            if m:
                ex.add(_h(m.group(1)))
    return ex

def _year(s: str) -> int:
    m = re.match(r"(\d{4})", str(s) or "")
    return int(m.group(1)) if m else 0

def build(n: int, out: Path) -> None:
    from datasets import load_dataset
    print("CVEfixes 스트리밍 로드 중…")
    ds = load_dataset("hitoshura25/cvefixes", split="train", streaming=True)

    train_h = _train_hashes()
    print(f"학습셋 제외 해시 {len(train_h)}개")

    seen: set[str] = set()
    by_lang_vuln: dict[str, list] = {}
    by_lang_safe: dict[str, list] = {}
    scanned = 0
    for r in ds:
        scanned += 1
        if scanned > 60000:
            break
        lang_raw = str(r.get("language", "")).strip().lower()
        lang = LANG_MAP.get(lang_raw)
        if not lang:
            continue
        if _year(r.get("published_date")) < MIN_YEAR:
            continue
        cwe = r.get("cwe_id") or ""
        cve = r.get("cve_id") or ""
        sev = str(r.get("severity") or "").upper()
        vuln_code = (r.get("vulnerable_code") or "").strip()
        fixed_code = (r.get("fixed_code") or "").strip()
        # 패치 전후가 동일하면(메타 변경 등) 스킵
        if _norm(vuln_code) == _norm(fixed_code):
            continue
        for code, label, bucket in ((vuln_code, "vuln", by_lang_vuln),
                                    (fixed_code, "safe", by_lang_safe)):
            if not (MIN_LEN <= len(code) <= MAX_LEN):
                continue
            hh = _h(code)
            if hh in train_h or hh in seen:
                continue
            seen.add(hh)
            bucket.setdefault(lang, []).append({
                "language": lang, "code": code, "label": label,
                "cwe": cwe, "cve": cve, "severity": sev,
                "published": str(r.get("published_date"))[:10],
            })

    # 언어 균등 + vuln/safe 균형으로 n개 샘플
    import random
    rng = random.Random(41)
    langs = sorted(set(by_lang_vuln) | set(by_lang_safe))
    per_lang = max(2, n // (2 * max(1, len(langs))))
    rows = []
    for lang in langs:
        for bucket in (by_lang_vuln, by_lang_safe):
            items = bucket.get(lang, [])
            rng.shuffle(items)
            rows.extend(items[:per_lang])
    rng.shuffle(rows)
    rows = rows[:n]

    out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
    from collections import Counter
    nv = sum(1 for r in rows if r["label"] == "vuln")
    print("─" * 60)
    print(f"스캔 {scanned}행 → 벤치 {len(rows)}개 (취약 {nv} / 안전 {len(rows)-nv})")
    print("언어:", dict(Counter(r["language"] for r in rows)))
    print("CWE Top:", dict(Counter(r["cwe"] for r in rows).most_common(8)))
    print("연도:", dict(Counter(r["published"][:4] for r in rows)))
    print(f"저장: {out}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=160)
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "cvefixes_benchmark.jsonl")
    a = ap.parse_args()
    build(a.n, a.out)
