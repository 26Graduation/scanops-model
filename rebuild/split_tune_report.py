"""
ScanOps v3 — 외부 벤치 tune/report 분할 (사양서 §3.4)
=====================================================
운영점(임계값·투표수·앙상블 가중치)을 test에서 고르면 과적합이다.
각 외부 test에서 층화 20%를 tune split으로 떼고, 최종 보고는 나머지 80%(report)에서.

원칙:
  - 시드 42 고정
  - 쌍(pair_id)은 쌍째로 이동 — 한쪽만 tune에 가면 쌍 단위 지표가 깨진다
  - 층화 키 = (lang_group) — 쌍 안에서 label은 이미 vuln/safe 하나씩이라 자동 균형
  - 원본 파일은 절대 수정하지 않는다(읽기만). 산출물은 새 파일.

출력: data/{name}_tune.jsonl, data/{name}_report.jsonl
실행: python rebuild/split_tune_report.py
"""
from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from pathlib import Path

SEED = 42
TUNE_FRAC = 0.20
DATA = Path(__file__).resolve().parent / "data"
NAMES = ["primevul_test", "cleanvul_v2_test"]


def main() -> None:
    summary = {}
    for name in NAMES:
        rows = [json.loads(l) for l in (DATA / f"{name}.jsonl").open()]
        # 그룹 키: pair_id 있으면 쌍째로, 없으면 개별 (빈 문자열 붕괴 방지)
        groups: dict[str, list[dict]] = defaultdict(list)
        for i, r in enumerate(rows):
            pid = r["meta"].get("pair_id")
            groups[pid if pid else f"single:{i}"].append(r)

        # 층화: lang_group별로 그룹을 나눠 각각 20%를 tune으로
        by_lang: dict[str, list[str]] = defaultdict(list)
        for k, items in groups.items():
            by_lang[items[0]["meta"]["lang_group"]].append(k)

        rng = random.Random(SEED)
        tune_keys: set[str] = set()
        for lang, keys in sorted(by_lang.items()):
            keys = sorted(keys)          # 재현성: 정렬 후 셔플
            rng.shuffle(keys)
            n = max(1, round(len(keys) * TUNE_FRAC))
            tune_keys.update(keys[:n])

        splits = {"tune": [], "report": []}
        for k, items in groups.items():
            splits["tune" if k in tune_keys else "report"].extend(items)

        summary[name] = {}
        for part, items in splits.items():
            path = DATA / f"{name.replace('_test','')}_{part}.jsonl"
            with path.open("w") as f:
                for s in items:
                    f.write(json.dumps(s, ensure_ascii=False) + "\n")
            c = Counter(s["meta"]["label"] for s in items)
            lc = Counter(s["meta"]["lang_group"] for s in items)
            summary[name][part] = {"n": len(items), "vuln": c["vuln"], "safe": c["safe"],
                                   "lang": dict(lc), "path": path.name}
            print(f"{path.name}: {len(items)}건 (vuln {c['vuln']} / safe {c['safe']}) {dict(lc)}")

    (Path(__file__).resolve().parent / "out" / "v3_tune_report_split.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
