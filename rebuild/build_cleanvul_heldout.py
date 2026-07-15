"""
ScanOps 재구축 — CleanVul held-out(최신 30%)을 v2 외부 평가셋으로 변환
=======================================================================
build_dataset_v2.py가 남긴 data/cleanvul_heldout_raw.json(원본 행)을
build_external_bench.py와 같은 형식(취약/안전 쌍, 우리 프롬프트)으로 전개한다.
이건 v2 학습에 안 쓴 데이터라 CleanVul 평가 자격을 유지한다(시간 분할).

dedup은 v2 학습셋(train_v2/val_v2)의 코드 해시와 대조 — held-out이 학습과
겹치지 않도록. CWE 없으니 이진+쌍 단위 채점만(build_external_bench와 동일).

출력: data/cleanvul_v2_test.jsonl
실행: .venv/bin/python rebuild/build_cleanvul_heldout.py
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
MIN_CHARS, MAX_CHARS = 40, 12_000
EXT_LANG = {"c": "C", "cpp": "C++", "java": "Java", "js": "JavaScript", "py": "Python"}
LANG_GROUP = {"Python": "Python", "JavaScript": "JS/TS", "Java": "Java", "C": "C/C++", "C++": "C/C++"}
PROMPT_TMPL = ("Analyze the following {language} code for security vulnerabilities.\n\n"
               "```{language}\n{code}\n```\n\n"
               "Respond in exactly this format:\n"
               "VULNERABILITY: <CWE-id (CWE name)> or NONE\n"
               "SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN> or NONE\n"
               "CVSS: <score 0.0-10.0> or 0.0\n"
               "REASON: <one-line explanation> or NONE")


def h(code: str) -> str:
    return hashlib.sha1(re.sub(r"\s+", " ", code).strip().lower().encode()).hexdigest()


def train_fingerprints() -> tuple[set[str], set[str]]:
    hs: set[str] = set()
    cves: set[str] = set()
    for split in ("train_v2", "val_v2"):
        for row in (json.loads(l) for l in (DATA / f"{split}.jsonl").open()):
            m = re.search(r"```[^\n]*\n(.*?)\n```", row["prompt"], re.S)
            if m:
                hs.add(h(m.group(1)))
            cves.add(row["meta"].get("cve_id", ""))
    cves.discard("")
    return hs, cves


def main() -> None:
    rows = json.loads((DATA / "cleanvul_heldout_raw.json").read_text())
    learned, learned_cves = train_fingerprints()
    out: list[dict] = []
    seen: set[str] = set()
    stats = Counter(rows_total=len(rows))

    for i, r in enumerate(rows):
        lang = EXT_LANG.get((r.get("extension") or "").strip().lower())
        if lang is None:
            stats["drop_language"] += 1
            continue
        vc, sc = (r.get("func_before") or "").strip(), (r.get("func_after") or "").strip()
        if not all(MIN_CHARS <= len(c) <= MAX_CHARS for c in (vc, sc)):
            stats["drop_length"] += 1
            continue
        hv, hs = h(vc), h(sc)
        if hv == hs or hv in seen or hs in seen:
            stats["drop_dup"] += 1
            continue
        cve = (r.get("cve_id") or "").strip()
        if hv in learned or hs in learned or (cve and cve in learned_cves):  # v2 학습과 겹치면 제외
            stats["drop_leak_train"] += 1
            continue
        seen.add(hv); seen.add(hs)
        pid = f"cvh_{i}"
        common = {"source": "cleanvul_heldout", "cve_id": (r.get("cve_id") or "").strip(),
                  "cwe_id": "", "language": lang, "lang_group": LANG_GROUP[lang],
                  "date": r.get("date", "")}
        for code, label in ((vc, "vuln"), (sc, "safe")):
            out.append({"prompt": PROMPT_TMPL.format(language=lang, code=code),
                        "meta": {**common, "pair_id": pid, "label": label}})
        stats["keep_pairs"] += 1

    path = DATA / "cleanvul_v2_test.jsonl"
    with path.open("w") as f:
        for s in out:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"CleanVul v2 held-out: {stats['keep_pairs']}쌍 = {len(out)}건 → {path}")
    print("언어:", dict(Counter(s["meta"]["lang_group"] for s in out)))
    print("통계:", dict(stats))


if __name__ == "__main__":
    main()
