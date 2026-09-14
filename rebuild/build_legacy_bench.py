"""
레거시 벤치(CVEfixes 157 / CyberNative 154)를 rebuild 프롬프트 형식으로 변환
====================================================================
왜: 운영점(OP) 표를 CleanVul/PrimeVul 두 개로만 내면 "외부 분포" 표본이 2개다.
    v12~v16 세대에서 쓰던 벤치 2종이 repo 에 남아 있으므로(data/), 같은 프롬프트·
    같은 채점기로 다시 재서 표를 넓힌다.

**반드시 먼저 확인해야 하는 것 — 누수.**
  rebuild 의 내부 train/test 는 CVEfixes 에서 만들어졌다(build_external_bench.py docstring).
  따라서 `data/cvefixes_benchmark.jsonl`(157건)은 rebuild train_v3 와 겹칠 수 있다.
  build_dataset.py 와 **동일한 정규화 코드 해시**로 겹침을 재고, 겹치는 건을 제거한다.
  제거 후 건수를 그대로 보고한다. 겹침이 크면 그 사실 자체가 결과다.
  CyberNative 는 독립 출처라 겹침이 없을 것으로 예상하나, **같은 검사를 똑같이 돌린다.**

출력: rebuild/data/{cvefixes157,cybernative154}.jsonl  (+ _leak.json)
실행: python3 rebuild/build_legacy_bench.py       (CPU, $0)
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent          # rebuild/
REPO = ROOT.parent                              # scanops-model/
DATA = ROOT / "data"

PROMPT_TMPL = """Analyze the following {language} code for security vulnerabilities.

```{language}
{code}
```

Respond in exactly this format:
VULNERABILITY: <CWE-id (CWE name)> or NONE
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN> or NONE
CVSS: <score 0.0-10.0> or 0.0
REASON: <one-line explanation> or NONE"""

# build_external_bench.py 와 동일한 길이 필터
MIN_CHARS, MAX_CHARS = 40, 12_000

SOURCES = {
    "cvefixes157": REPO / "data" / "cvefixes_benchmark.jsonl",
    "cybernative154": REPO / "data" / "cybernative_benchmark.jsonl",
}


def code_hash(code: str) -> str:
    """build_dataset.py / build_external_bench.py 와 동일한 정규화 해시."""
    return hashlib.sha1(re.sub(r"\s+", " ", code).strip().lower().encode()).hexdigest()


def train_hashes() -> set[str]:
    """rebuild 학습·검증에 들어간 코드의 해시 집합."""
    hs: set[str] = set()
    for f in ("train_v3.jsonl", "val_v3.jsonl"):
        p = DATA / f
        if not p.exists():
            raise SystemExit(f"없는 파일: {p}")
        for line in p.open():
            r = json.loads(line)
            # 프롬프트에서 코드 펜스 안쪽만 뽑는다 (프롬프트 템플릿이 동일하므로 안전)
            m = re.search(r"```[^\n]*\n(.*?)\n```", r["prompt"], re.S)
            if m:
                hs.add(code_hash(m.group(1)))
    return hs


def main() -> None:
    train = train_hashes()
    print(f"[train] 고유 코드 해시 {len(train):,}")

    summary = {}
    for name, src in SOURCES.items():
        rows = [json.loads(l) for l in src.open()]
        n_in = len(rows)

        kept, dropped_leak, dropped_len = [], 0, 0
        for i, r in enumerate(rows):
            code = r["code"]
            if not (MIN_CHARS <= len(code) <= MAX_CHARS):
                dropped_len += 1
                continue
            if code_hash(code) in train:
                dropped_leak += 1
                continue
            lang = r.get("language", "code")
            kept.append({
                "prompt": PROMPT_TMPL.format(language=lang, code=code),
                "meta": {
                    "source": name,
                    "cve_id": r.get("cve", ""),
                    "cwe_id": r.get("cwe", ""),
                    "language": lang,
                    "lang_group": lang,
                    "pair_id": f"{name}_{i}",
                    "label": r["label"],
                },
            })

        out = DATA / f"{name}.jsonl"
        with out.open("w") as f:
            for r in kept:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

        lab = Counter(r["meta"]["label"] for r in kept)
        summary[name] = {
            "src": str(src.relative_to(REPO)),
            "n_in": n_in,
            "n_dropped_leak_vs_train_v3": dropped_leak,
            "n_dropped_length_filter": dropped_len,
            "n_out": len(kept),
            "labels": dict(lab),
            "balanced": lab.get("vuln") == lab.get("safe"),
        }
        print(f"[{name}] {n_in} → {len(kept)}  "
              f"(누수 제거 {dropped_leak}, 길이 제거 {dropped_len})  {dict(lab)}")

    (ROOT / "out" / "legacy_bench_leak.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2))
    print("→ out/legacy_bench_leak.json")


if __name__ == "__main__":
    main()
