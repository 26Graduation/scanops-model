"""
Phase 1 프롬프트 빌더 — diff 를 보여주는 네 가지 형식 (사양 DIFF_AWARE_RUN_SPEC.md §5)
=========================================================================================
유사도 0.95+ 쌍에서 층화 표본 200쌍(=400건)을 뽑아, arm 별로 채점용 jsonl 을 만든다.

**누수 규칙(§4)을 코드로 강제한다.**
  - 두 판본은 `Version A` / `Version B`. **어느 쪽이 A 인지 쌍마다 무작위**(seed 42).
  - 금지어(`before/after/fix/patch/commit/old/new/...`)를 프롬프트에 쓰지 않는다.
    빌드 후 **자동 검사**로 확인하고, 걸리면 예외를 던진다.
  - 각 쌍을 **양방향**(A 판정 1회, B 판정 1회)으로 만든다.
  - **이 빌더는 라벨을 보지 않는다.** A/B 배정도 라벨과 무관한 난수로 한다.
    그 사실을 `-shuf` arm 이 검정한다 — 라벨을 절반 뒤집어도 프롬프트가 같으면
    순위 정확도가 정확히 0.5 로 수렴한다. 0.55 를 넘으면 빌더가 라벨을 흘린 것이다.

arm: P0(현행) / P1(diff 블록) / P2([DIFF] 마커) / P3(양쪽 제시) + P1shuf / P3shuf
회귀: 내부 test 100 + CyberNative 50 을 P0/P1/P2 형식으로 (diff 자리에 `(none)`)

실행: python3 rebuild/build_diff_prompts.py
출력: data/dw_{arm}.jsonl, data/dw_reg_{arm}.jsonl, out/dw_sample.json
"""
from __future__ import annotations

import difflib
import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CODE = re.compile(r"```[^\n]*\n(.*?)\n```", re.S)
SEED = 42
QUOTA = {"CleanVul": 120, "PrimeVul": 70, "내부test": 10}
SPLIT_OF = {"CleanVul": "cleanvul_v2_report", "PrimeVul": "primevul_report", "내부test": "test"}
REG_N = {"test": 100, "cybernative154": 50}

# §4 금지어 — 시간 순서·수정 의도를 흘리는 단어
BANNED = re.compile(
    r"\b(previous|current|before|after|fix|fixes|fixed|patch|patched|patches|"
    r"commit|committed|old|new|original|updated|prior|later|earlier)\b", re.I)

RESPOND = """Respond in exactly this format:
VULNERABILITY: <CWE-id (CWE name)> or NONE
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN> or NONE
CVSS: <score 0.0-10.0> or 0.0
REASON: <one-line explanation> or NONE"""

LINE_COMMENT = {
    "Python": "#", "PHP": "//", "Java": "//", "JS/TS": "//", "C/C++": "//",
    "Ruby": "#", "Go": "//", "C#": "//", "Node.js / Express": "//",
    "TypeScript": "//", "C": "//", "C++": "//",
}


def comment_of(lang: str | None) -> str:
    return LINE_COMMENT.get(lang or "", "//")


def code_of(p: str) -> str:
    m = CODE.search(p)
    return m.group(1) if m else p


def pair_key(m: dict) -> str | None:
    return m.get("pair_id") or m.get("cve_id") or None


def hunk(a: str, b: str) -> str:
    """A→B 줄 단위 차이. '-' = Version A 에만, '+' = Version B 에만.

    A/B 배정이 쌍마다 무작위이므로 이 방향은 라벨 정보를 담지 않는다(§4-2).
    """
    out = []
    sm = difflib.SequenceMatcher(None, a.splitlines(), b.splitlines())
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        for l in a.splitlines()[i1:i2]:
            out.append(f"- {l}")
        for l in b.splitlines()[j1:j2]:
            out.append(f"+ {l}")
    return "\n".join(out) if out else "(none)"


def changed_line_idx(this: str, other: str) -> set[int]:
    """`this` 안에서 `other` 와 다른 줄의 인덱스."""
    idx = set()
    sm = difflib.SequenceMatcher(None, this.splitlines(), other.splitlines())
    for tag, i1, i2, _j1, _j2 in sm.get_opcodes():
        if tag != "equal":
            idx.update(range(i1, i2))
    return idx


# ── arm 별 프롬프트 ──────────────────────────────────────────────────────────
def p0(lang: str, code: str, **_) -> str:
    return (f"Analyze the following {lang} code for security vulnerabilities.\n\n"
            f"```{lang}\n{code}\n```\n\n{RESPOND}")


def p1(lang: str, code: str, this_v: str, hunk_txt: str, **_) -> str:
    return (f"Analyze the following {lang} code for security vulnerabilities.\n"
            f"This is Version {this_v}.\n\n"
            f"```{lang}\n{code}\n```\n\n"
            f"Lines that differ between Version A and Version B "
            f"('-' = only in Version A, '+' = only in Version B):\n"
            f"```\n{hunk_txt}\n```\n\n{RESPOND}")


def p2(lang: str, code: str, this_v: str, marked: str, **_) -> str:
    c = comment_of(lang)
    return (f"Analyze the following {lang} code for security vulnerabilities.\n"
            f"This is Version {this_v}. Lines that differ from the other version are "
            f"preceded by a `{c} [DIFF]` marker.\n\n"
            f"```{lang}\n{marked}\n```\n\n{RESPOND}")


def p3(lang: str, code_a: str, code_b: str, ask: str, **_) -> str:
    return (f"Two versions of the same {lang} code are shown below.\n\n"
            f"Version A:\n```{lang}\n{code_a}\n```\n\n"
            f"Version B:\n```{lang}\n{code_b}\n```\n\n"
            f"Assess Version {ask} for security vulnerabilities.\n\n{RESPOND}")


def mark(code: str, idx: set[int], c: str) -> str:
    out = []
    for i, l in enumerate(code.splitlines()):
        if i in idx:
            indent = l[:len(l) - len(l.lstrip())]
            out.append(f"{indent}{c} [DIFF]")
        out.append(l)
    return "\n".join(out)


def main() -> None:
    rng = random.Random(SEED)

    # ── 표본 추출 ────────────────────────────────────────────────────────
    hi = [json.loads(l) for l in (ROOT / "out" / "phase0_sim95_pairs.jsonl").open()]
    by_bench = defaultdict(list)
    for r in hi:
        by_bench[r["bench"]].append(r)
    sample = []
    for bench, q in QUOTA.items():
        pool = sorted(by_bench[bench], key=lambda r: r["case_id"])
        rng.shuffle(pool)
        sample += pool[:q]
    print(f"[표본] {len(sample)}쌍  " + "  ".join(
        f"{b}={sum(1 for r in sample if r['bench']==b)}" for b in QUOTA))

    # ── 원본 코드 로드 ───────────────────────────────────────────────────
    data = {}
    for bench, split in SPLIT_OF.items():
        for r in (json.loads(l) for l in (ROOT / "data" / f"{split}.jsonl").open()):
            data[(split, pair_key(r["meta"]), r["meta"]["label"])] = r

    arms: dict[str, list[dict]] = defaultdict(list)
    meta_rows = []
    for n, r in enumerate(sample):
        sp, cid = r["split"], r["case_id"]
        dv, ds = data.get((sp, cid, "vuln")), data.get((sp, cid, "safe"))
        if dv is None or ds is None:
            continue
        lang = dv["meta"].get("lang_group") or "code"
        cv, cs = code_of(dv["prompt"]), code_of(ds["prompt"])

        prng = random.Random(f"{SEED}:{cid}")
        vuln_is_a = prng.random() < 0.5          # ← 라벨과 무관. A/B 배정만 결정
        code_a, code_b = (cv, cs) if vuln_is_a else (cs, cv)
        h = hunk(code_a, code_b)
        c = comment_of(lang)

        # 라벨 셔플 (누수 대조군): 쌍의 절반에서 라벨을 뒤집는다
        swap = prng.random() < 0.5

        for ver, code, other in (("A", code_a, code_b), ("B", code_b, code_a)):
            is_vuln = (ver == "A") == vuln_is_a
            true_label = "vuln" if is_vuln else "safe"
            shuf_label = ("safe" if is_vuln else "vuln") if swap else true_label
            base = {"source": "diff_aware", "pair_id": f"{r['bench']}|{cid}",
                    "language": lang, "lang_group": lang, "bench": r["bench"],
                    "judged_version": ver, "sim": r["sim"],
                    "changed_lines": r["changed_lines"]}
            mk = mark(code, changed_line_idx(code, other), c)
            for arm, text, lab in (
                ("P0", p0(lang, code), true_label),
                ("P1", p1(lang, code, ver, h), true_label),
                ("P2", p2(lang, code, ver, mk), true_label),
                ("P3", p3(lang, code_a, code_b, ver), true_label),
                ("P1shuf", p1(lang, code, ver, h), shuf_label),
                ("P3shuf", p3(lang, code_a, code_b, ver), shuf_label),
            ):
                arms[arm].append({"prompt": text, "meta": {**base, "label": lab}})
        meta_rows.append({"case_id": cid, "bench": r["bench"], "lang": lang,
                          "vuln_is_a": vuln_is_a, "label_swapped": swap,
                          "sim": r["sim"], "changed_lines": r["changed_lines"]})

    # ── 금지어 검사 (§4-2) ───────────────────────────────────────────────
    # 코드/hunk 는 **데이터**이고 `new`·`old` 같은 단어가 식별자로 들어 있다.
    # 우리가 쓴 **지시문**만 검사해야 한다 — 모든 ``` 블록을 통째로 제거하고 본다.
    FENCE = re.compile(r"```.*?```", re.S)
    hits = Counter()
    for arm, rows in arms.items():
        for row in rows:
            instr = FENCE.sub(" ", row["prompt"])
            for m in BANNED.finditer(instr):
                hits[(arm, m.group(0).lower())] += 1
    if hits:
        raise SystemExit(f"금지어가 지시문에 있다: {dict(hits)}")
    print("[검사] 지시문 금지어 0건 (코드/hunk 블록 제외 — 그 안의 new/old 등은 데이터다)")

    for arm, rows in arms.items():
        p = ROOT / "data" / f"dw_{arm}.jsonl"
        with p.open("w") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"  {p.name}: {len(rows)}건")

    # ── 단건 회귀 세트 ───────────────────────────────────────────────────
    reg_rng = random.Random(SEED)
    for split, n in REG_N.items():
        rows = [json.loads(l) for l in (ROOT / "data" / f"{split}.jsonl").open()]
        reg_rng.shuffle(rows)
        for arm in ("P0", "P1", "P2"):
            out = []
            for row in rows[:n]:
                lang = row["meta"].get("lang_group") or "code"
                code = code_of(row["prompt"])
                if arm == "P0":
                    t = p0(lang, code)
                elif arm == "P1":
                    t = p1(lang, code, "A", "(none)")
                else:
                    t = p2(lang, code, "A", code)     # 마커 없음 = 변경 줄 없음
                out.append({"prompt": t, "meta": {**row["meta"], "reg_split": split}})
            p = ROOT / "data" / f"dw_reg_{split}_{arm}.jsonl"
            with p.open("w") as f:
                for o in out:
                    f.write(json.dumps(o, ensure_ascii=False) + "\n")
            print(f"  {p.name}: {len(out)}건")

    (ROOT / "out" / "dw_sample.json").write_text(json.dumps({
        "seed": SEED, "quota": QUOTA, "n_pairs": len(meta_rows),
        "n_label_swapped": sum(r["label_swapped"] for r in meta_rows),
        "n_vuln_is_a": sum(r["vuln_is_a"] for r in meta_rows),
        "by_bench": dict(Counter(r["bench"] for r in meta_rows)),
        "by_lang": dict(Counter(r["lang"] for r in meta_rows)),
        "pairs": meta_rows}, ensure_ascii=False, indent=2))
    print(f"[표본 메타] out/dw_sample.json — 라벨 뒤집힌 쌍 "
          f"{sum(r['label_swapped'] for r in meta_rows)}/{len(meta_rows)}, "
          f"vuln=A 인 쌍 {sum(r['vuln_is_a'] for r in meta_rows)}/{len(meta_rows)}")


if __name__ == "__main__":
    main()
