"""완전 독립 벤치마크 — DiverseVul (학습에 한 번도 안 쓴 출처)
================================================================
사용자 지적: CVEfixes·CyberNative 벤치는 학습과 **같은 데이터셋 출처**(CVE-id만 분리).
→ 도메인 적응 효과가 섞임. 진짜 일반화는 **학습에 안 쓴 다른 출처**로 측정해야 한다.

출처: HuggingFace `claudios/DiverseVul` — 실제 커밋에서 추출한 C/C++ 취약/정상 함수.
  (cvefixes·CyberNative와 별개 수집본. target=1 취약 / 0 정상.)

누수 차단: v13·v14 **학습셋 코드해시로 dedup** → 우연한 코드 겹침도 제거.
  (C/C++는 그래프 미커버라, 이 벤치는 순수 LLM 일반화 측정용.)

실행: python scripts/build_diversevul_benchmark.py --n 150
산출: data/diversevul_benchmark.jsonl ({language, code, label, cwe})
"""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIN_LEN, MAX_LEN = 60, 2000     # C 함수는 길어 상한↑

def _norm(c): return re.sub(r"\s+", " ", c or "").strip().lower()
def _h(c): return hashlib.sha1(_norm(c).encode()).hexdigest()

def _train_hashes() -> set[str]:
    ex = set()
    for name in ("lora_train_v13.jsonl","lora_train_v13_val.jsonl",
                 "lora_train_v14.jsonl","lora_train_v14_val.jsonl"):
        p = ROOT / "data" / name
        if not p.exists(): continue
        for line in p.read_text().splitlines():
            if not line.strip(): continue
            m = re.search(r"```[a-zA-Z+#./]*\n(.*?)```", json.loads(line)["prompt"], re.S)
            if m: ex.add(_h(m.group(1)))
    return ex

def build(n: int, out: Path):
    from datasets import load_dataset
    train_h = _train_hashes()
    print(f"v13/v14 학습셋 제외 해시 {len(train_h)}개")
    ds = load_dataset("claudios/DiverseVul", split="test", streaming=True)

    seen=set(); vuln=[]; safe=[]; scanned=0; leaked=0
    for r in ds:
        scanned += 1
        if scanned > 40000 or (len(vuln) >= n and len(safe) >= n): break
        code = (r.get("func") or "").strip()
        if not (MIN_LEN <= len(code) <= MAX_LEN): continue
        hh = _h(code)
        if hh in train_h:
            leaked += 1; continue
        if hh in seen: continue
        seen.add(hh)
        label = "vuln" if r.get("target") == 1 else "safe"
        row = {"language": "C", "code": code, "label": label, "cwe": str(r.get("cwe") or "")}
        (vuln if label == "vuln" else safe).append(row)

    import random
    rng = random.Random(41)
    rng.shuffle(vuln); rng.shuffle(safe)
    k = n // 2
    rows = vuln[:k] + safe[:k]
    rng.shuffle(rows)
    out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
    print("─"*60)
    print(f"스캔 {scanned} · 학습겹침 제거 {leaked} → 벤치 {len(rows)} (취약 {sum(1 for r in rows if r['label']=='vuln')}/안전 {sum(1 for r in rows if r['label']=='safe')})")
    print(f"저장: {out}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=150)
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "diversevul_benchmark.jsonl")
    a = ap.parse_args()
    build(a.n, a.out)
