"""제3 벤치마크 빌더 — CyberNative DPO (CVEfixes와 독립, 다언어, 그래프 커버)
================================================================
목적: V13는 CVEfixes로 학습했으므로 CVEfixes held-out엔 同분포 효과가 섞인다.
      **완전히 다른 출처**의 벤치로 일반화를 정직하게 검증한다.

출처: HuggingFace `CyberNative/Code_Vulnerability_Security_DPO`
  - 10개 언어 secure/insecure 코드쌍. `rejected`=취약, `chosen`=안전.
  - CVE 커밋이 아닌 별도 생성 데이터 → v13 학습(cvefixes)과 출처가 다름 = 독립.

설계:
  - **그래프 커버 언어만** 사용(Python/Java/JS/PHP/Ruby/Go/C#) → 3-way(모델/+그래프/Grok) 의미.
  - rejected→vuln, chosen→safe (자연 균형). 코드펜스 안만 추출.
  - 코드해시 dedup + v13 학습셋 코드해시 제외(누수 0 보장).

실행: python scripts/build_cybernative_benchmark.py --n 160
산출: data/cybernative_benchmark.jsonl ({language, code, label, lang_raw, cwe})
"""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# 그래프가 커버하는 언어만 (multi_graph._lang_key 기준) → 표준 라벨
LANG_MAP = {
    "python": "Python", "java": "Java", "javascript": "Node.js / Express",
    "php": "PHP", "ruby": "Ruby", "go": "Go", "c#": "C#",
}
MIN_LEN, MAX_LEN = 40, 1600

def _norm(c): return re.sub(r"\s+", " ", c or "").strip().lower()
def _h(c): return hashlib.sha1(_norm(c).encode()).hexdigest()

def _extract_code(md: str) -> str:
    """```lang\\n...\\n``` 펜스 안 코드 추출(없으면 원문)."""
    m = re.search(r"```[a-zA-Z+#0-9./]*\n(.*?)```", md or "", re.S)
    return (m.group(1) if m else (md or "")).strip()

def _train_hashes() -> set[str]:
    ex = set()
    for name in ("lora_train_v13.jsonl", "lora_train_v13_val.jsonl"):
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

def build(n: int, out: Path) -> None:
    from datasets import load_dataset
    train_h = _train_hashes()
    print(f"v13 학습셋 제외 해시 {len(train_h)}개")
    ds = load_dataset("CyberNative/Code_Vulnerability_Security_DPO", split="train", streaming=True)

    seen: set[str] = set()
    by_lang_vuln: dict[str, list] = defaultdict(list)
    by_lang_safe: dict[str, list] = defaultdict(list)
    scanned = 0
    for r in ds:
        scanned += 1
        if scanned > 20000:
            break
        lang = LANG_MAP.get(str(r.get("lang", "")).strip().lower())
        if not lang:
            continue
        cwe = (r.get("vulnerability") or "")[:60]
        for md, label, bucket in ((r.get("rejected"), "vuln", by_lang_vuln),
                                  (r.get("chosen"), "safe", by_lang_safe)):
            code = _extract_code(md)
            if not (MIN_LEN <= len(code) <= MAX_LEN):
                continue
            hh = _h(code)
            if hh in train_h or hh in seen:
                continue
            seen.add(hh)
            bucket[lang].append({"language": lang, "code": code, "label": label,
                                 "lang_raw": str(r.get("lang")), "cwe": cwe})

    import random
    rng = random.Random(41)
    langs = sorted(set(by_lang_vuln) | set(by_lang_safe))
    per = max(2, n // (2 * max(1, len(langs))))
    rows = []
    for lang in langs:
        for bucket in (by_lang_vuln, by_lang_safe):
            items = bucket.get(lang, [])
            rng.shuffle(items)
            rows.extend(items[:per])
    rng.shuffle(rows)
    rows = rows[:n]

    out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
    nv = sum(1 for r in rows if r["label"] == "vuln")
    print("─" * 60)
    print(f"스캔 {scanned} → 벤치 {len(rows)} (취약 {nv} / 안전 {len(rows)-nv})")
    print("언어:", dict(Counter(r["language"] for r in rows)))
    print(f"저장: {out}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=160)
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "cybernative_benchmark.jsonl")
    a = ap.parse_args()
    build(a.n, a.out)
