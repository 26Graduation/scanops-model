"""
위치 상쇄 재측정용 프롬프트 빌더 (사양 DIFF_AWARE_RUN_SPEC.md §10-3)
=====================================================================
Phase 1 에서 P1·P3 가 "Version A 를 더 취약하다고 본다"는 위치 선호를 만드는 것이 드러났다
(P(A>B) 0.70 / 0.735, vuln=A 정확도와 vuln=B 정확도의 격차 +0.46 / +0.54).

그래서 같은 200쌍을 **두 배정 모두**로 만든다:
  배정 X — 취약본 = Version A
  배정 Y — 취약본 = Version B
각 배정에서 양방향 채점(A 판정·B 판정) → arm 당 800건.
더해지는 위치 항은 두 배정에서 부호가 반대라 평균 `acc_cb` 에서 상쇄된다.

`build_diff_prompts.py` 의 프롬프트 함수를 그대로 가져다 쓴다 —
**형식이 달라지면 비교가 성립하지 않기 때문이다.**

실행: python3 rebuild/build_diff_cb.py
출력: data/dw_cbX_{P1,P2,P3}.jsonl, data/dw_cbY_{P1,P2,P3}.jsonl
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from build_diff_prompts import (BANNED, QUOTA, SEED, SPLIT_OF, changed_line_idx,
                                code_of, comment_of, hunk, mark, p1, p2, p3, pair_key)

ROOT = Path(__file__).resolve().parent
FENCE = re.compile(r"```.*?```", re.S)


def main() -> None:
    # Phase 1 과 **정확히 같은 200쌍**을 쓴다 — 표본이 달라지면 비교가 깨진다.
    samp = json.load((ROOT / "out" / "dw_sample.json").open())["pairs"]
    print(f"[표본] Phase 1 과 동일한 {len(samp)}쌍 재사용  " +
          "  ".join(f"{b}={sum(1 for r in samp if r['bench']==b)}" for b in QUOTA))

    data = {}
    for bench, split in SPLIT_OF.items():
        for r in (json.loads(l) for l in (ROOT / "data" / f"{split}.jsonl").open()):
            data[(split, pair_key(r["meta"]), r["meta"]["label"])] = r

    out: dict[str, list[dict]] = defaultdict(list)
    for r in samp:
        split = SPLIT_OF[r["bench"]]
        dv, ds = data.get((split, r["case_id"], "vuln")), data.get((split, r["case_id"], "safe"))
        if dv is None or ds is None:
            continue
        lang = dv["meta"].get("lang_group") or "code"
        cv, cs = code_of(dv["prompt"]), code_of(ds["prompt"])
        c = comment_of(lang)

        for assign, (code_a, code_b) in (("X", (cv, cs)), ("Y", (cs, cv))):
            # X: 취약본이 A / Y: 취약본이 B
            h = hunk(code_a, code_b)
            for ver, code, other in (("A", code_a, code_b), ("B", code_b, code_a)):
                is_vuln = (ver == "A") == (assign == "X")
                meta = {"source": "diff_aware_cb", "pair_id": f"{r['bench']}|{r['case_id']}",
                        "language": lang, "lang_group": lang, "bench": r["bench"],
                        "assign": assign, "judged_version": ver, "sim": r["sim"],
                        "changed_lines": r["changed_lines"],
                        "label": "vuln" if is_vuln else "safe"}
                mk = mark(code, changed_line_idx(code, other), c)
                out[f"cb{assign}_P1"].append({"prompt": p1(lang, code, ver, h), "meta": meta})
                out[f"cb{assign}_P2"].append({"prompt": p2(lang, code, ver, mk), "meta": meta})
                out[f"cb{assign}_P3"].append({"prompt": p3(lang, code_a, code_b, ver), "meta": meta})

    hits = Counter()
    for name, rows in out.items():
        for row in rows:
            for m in BANNED.finditer(FENCE.sub(" ", row["prompt"])):
                hits[(name, m.group(0).lower())] += 1
    if hits:
        raise SystemExit(f"금지어가 지시문에 있다: {dict(hits)}")
    print("[검사] 지시문 금지어 0건")

    for name, rows in out.items():
        p = ROOT / "data" / f"dw_{name}.jsonl"
        with p.open("w") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        n_v = sum(1 for r in rows if r["meta"]["label"] == "vuln")
        print(f"  {p.name}: {len(rows)}건 (vuln {n_v} / safe {len(rows)-n_v})")


if __name__ == "__main__":
    main()
