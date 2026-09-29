from datasets import load_dataset
from collections import Counter

print("Loading hitoshura25/cvefixes (streaming)...", flush=True)
ds = load_dataset("hitoshura25/cvefixes", split="train", streaming=True)

langs = Counter()
for i, row in enumerate(ds):
    langs[str(row.get("language") or "").strip().lower()] = langs.get(str(row.get("language") or "").strip().lower(), 0)
    langs[str(row.get("language") or "").strip().lower()] += 1
    if i % 2000 == 0:
        print(f"...{i} rows processed", flush=True)

print("\n=== 전체 언어별 건수 (내림차순) ===")
total = sum(langs.values())
for lang, count in langs.most_common(30):
    print(f"{lang or '(empty)'}: {count}건 ({count/total*100:.1f}%)")

print(f"\n총 행 수: {total}")
