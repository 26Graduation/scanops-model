"""
V5-A 학습 데이터 빌더 — diff 조건부 입력 (사양 V5_TRAIN_RUN_SPEC.md §2·§3)
==============================================================================
`train_v3.jsonl` / `val_v3.jsonl` 의 **내용은 그대로 두고 입력 형식만 바꾼다.**
쌍(같은 `pair_id`)이 있는 샘플은 상대 판본과의 차이 블록을 붙이고,
쌍이 없는 샘플은 `(none)` 을 붙인다.

**바꾸는 것은 이것 하나뿐이다.** 베이스·rank·lr·데이터 구성·시드는 v1/v3 와 동일하다.

누수 규칙(D-20)을 학습 데이터에도 그대로 적용한다:
  - `Version A`/`Version B` 중립 라벨, **어느 쪽이 A 인지 쌍마다 무작위**(seed 42)
  - 금지어 자동 검사(지시문만 — 코드는 데이터다)
  - 시간 순서·수정 의도를 나타내는 표현 없음

**학습 데이터에서 순서를 흘리면, 그렇게 학습된 모델이 평가에서도 그 힌트를 찾는다.**

실행: python3 rebuild/build_train_v5.py [FORMAT]     (FORMAT: P1 | P2, 기본 P1)
출력: data/train_v5.jsonl, data/val_v5.jsonl, out/v5_data_stats.json
"""
from __future__ import annotations

import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from build_diff_prompts import (BANNED, SEED, changed_line_idx, code_of,
                                comment_of, hunk, mark, p1, p2, pair_key)

ROOT = Path(__file__).resolve().parent
FENCE = re.compile(r"```.*?```", re.S)
FMT = (sys.argv[1] if len(sys.argv) > 1 else "P1").upper()
assert FMT in ("P1", "P2"), "학습 형식은 P1 또는 P2 만 지원한다 (P3 는 컨텍스트가 2배라 예산 밖)"


def build(split: str) -> tuple[list[dict], dict]:
    rows = [json.loads(l) for l in (ROOT / "data" / f"{split}.jsonl").open()]
    by_pair = defaultdict(list)
    for i, r in enumerate(rows):
        k = pair_key(r["meta"])
        if k:
            by_pair[k].append(i)

    out, stats = [], Counter()
    for i, r in enumerate(rows):
        lang = r["meta"].get("lang_group") or r["meta"].get("language") or "code"
        code = code_of(r["prompt"])
        k = pair_key(r["meta"])
        partner = None
        if k and len(by_pair[k]) == 2:
            j = [x for x in by_pair[k] if x != i]
            if j:
                partner = code_of(rows[j[0]]["prompt"])

        if partner is None:
            stats["no_pair"] += 1
            # 쌍이 없으면 차이 블록은 (none). 판정 대상은 항상 Version A 로 둔다
            # — 상대가 없으므로 A/B 무작위가 의미가 없다.
            prompt = (p1(lang, code, "A", "(none)") if FMT == "P1"
                      else p2(lang, code, "A", code))
        else:
            stats["paired"] += 1
            prng = random.Random(f"{SEED}:{k}")
            this_is_a = prng.random() < 0.5          # ← 라벨과 무관
            code_a, code_b = (code, partner) if this_is_a else (partner, code)
            ver = "A" if this_is_a else "B"
            if FMT == "P1":
                prompt = p1(lang, code, ver, hunk(code_a, code_b))
            else:
                c = comment_of(lang)
                prompt = p2(lang, code, ver, mark(code, changed_line_idx(code, partner), c))

        new = dict(r)
        new["prompt"] = prompt
        out.append(new)
    return out, dict(stats)


def main() -> None:
    total = {}
    for split, dst in (("train_v3", "train_v5"), ("val_v3", "val_v5")):
        rows, stats = build(split)
        hits = Counter()
        for r in rows:
            for m in BANNED.finditer(FENCE.sub(" ", r["prompt"])):
                hits[m.group(0).lower()] += 1
        if hits:
            raise SystemExit(f"금지어가 지시문에 있다: {dict(hits)}")
        p = ROOT / "data" / f"{dst}.jsonl"
        with p.open("w") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        # 프롬프트 길이 변화 — 컨텍스트 예산 확인용
        old = [len(json.loads(l)["prompt"]) for l in (ROOT / "data" / f"{split}.jsonl").open()]
        new = [len(r["prompt"]) for r in rows]
        old.sort(); new.sort()
        total[dst] = {**stats, "n": len(rows),
                      "chars_median_before": old[len(old) // 2],
                      "chars_median_after": new[len(new) // 2],
                      "chars_p95_before": old[int(len(old) * .95)],
                      "chars_p95_after": new[int(len(new) * .95)]}
        print(f"[{dst}] {len(rows)}건 (쌍 {stats.get('paired',0)} / 무쌍 {stats.get('no_pair',0)})  "
              f"문자수 중앙값 {old[len(old)//2]} → {new[len(new)//2]}  "
              f"p95 {old[int(len(old)*.95)]} → {new[int(len(new)*.95)]}")
    total["format"] = FMT
    total["note"] = ("내용·라벨·시드·데이터 구성은 train_v3/val_v3 와 동일하다. "
                     "바뀐 것은 프롬프트 형식 하나뿐이다.")
    (ROOT / "out" / "v5_data_stats.json").write_text(json.dumps(total, ensure_ascii=False, indent=2))
    print("[검사] 지시문 금지어 0건")
    print("→ out/v5_data_stats.json")


if __name__ == "__main__":
    main()
