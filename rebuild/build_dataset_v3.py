"""
ScanOps 재구축 — v3 학습 데이터 빌더 (사양서 §4)
=================================================
v2 실패의 1차 원인(그룹 키 붕괴 → val 86% safe)을 고치고, 라벨/언어 층화를 강제한다.

v2 대비 수정 4가지:
  1. 그룹 키 붕괴 수정
     v2: groups[pair_id or cve_id]  → CleanVul은 pair_id=None, cve_id='' 라서
         3,617건이 '' 하나로 뭉쳐 통째로 val에 빠짐.
     v3: pair_id → cve_id → f"orphan:{code_hash}" 로 폴백. 빈 값이 절대 뭉치지 않음.
  2. val 층화 (10%): 쌍 소스(CVEfixes/PrimeVul)로 vuln:safe를 46:46 채우고,
     나머지 8%만 CleanVul safe-only로 채워 내부 test와 같은 54:46(safe:vuln)에 맞춘다.
     언어는 내부 test 분포를 목표로 공급 가능한 범위에서 비례 배분.
  3. CleanVul held-out(최신 30%)은 val에 넣지 않음 — 평가 전용(cleanvul_v2_test)이라 누수.
  4. 소스별 상한: CleanVul은 safe-only라 라벨을 SAFE 쪽으로 왜곡한다.
     train의 vuln 비율이 MIN_TRAIN_VULN_FRAC 아래로 떨어지지 않게 CleanVul을 잘라낸다.
     (v2는 이 상한이 없어 "항상 SAFE"가 최적해가 됐다)

무결성:
  - 평가 3종(test / primevul_test / cleanvul_v2_test)과 (cve_id, 정규화 코드 SHA1)로 dedup.
  - 평가 파일은 읽기만 한다.

출력: data/train_v3.jsonl, data/val_v3.jsonl, out/v3_data_stats.json
실행: python rebuild/build_dataset_v3.py
"""
from __future__ import annotations

import csv
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

from build_dataset import (
    LANG_GROUP, MAX_CHARS, MIN_CHARS, PROMPT_TMPL, SAFE_COMPLETION,
    code_hash, derive_severity, extract_reason, vuln_completion,
)
from build_dataset_v2 import CPP_EXTS, EXT_LANG, code_fence, existing_fingerprints

SEED = 42
ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
RAW = DATA / "raw"

CLEANVUL_TRAIN_FRAC = 0.70      # 시간분할: 오래된 70%만 학습 후보 (최신 30%는 평가셋)
VAL_FRAC = 0.10
VAL_VULN_TARGET = 0.46          # 내부 test와 동일한 라벨 비율 (safe 54 : vuln 46)
MIN_TRAIN_VULN_FRAC = 0.45      # 이 아래로 떨어지면 CleanVul safe를 잘라낸다


def group_key(s: dict) -> str:
    """v2 버그 수정 지점: 빈 문자열/None이 한 그룹으로 붕괴하지 않게 폴백을 3단으로."""
    m = s["meta"]
    pid = m.get("pair_id")
    if pid:
        return f"pair:{pid}"
    cve = (m.get("cve_id") or "").strip()
    if cve:
        return f"cve:{cve}"
    return f"orphan:{code_hash(code_fence(s['prompt']))}"


# ── 소스 로더 ────────────────────────────────────────────────────────────────
def load_base(seen: set[str]) -> list[dict]:
    """v1 train+val (CVEfixes). 이미 포맷·dedup 완료."""
    out = []
    for split in ("train", "val"):
        for row in (json.loads(l) for l in (DATA / f"{split}.jsonl").open()):
            row["meta"].setdefault("source", "cvefixes")
            row["meta"].setdefault("pair_id", f"cvefixes_{row['meta']['cve_id']}")
            out.append(row)
            seen.add(code_hash(code_fence(row["prompt"])))
    print(f"[CVEfixes] {len(out)}건")
    return out


def load_primevul(our_cves, our_hashes, seen, stats) -> list[dict]:
    rows = [json.loads(l) for l in (RAW / "primevul_train_paired.jsonl").open()]
    out: list[dict] = []
    for i in range(0, len(rows) - 1, 2):
        a, b = rows[i], rows[i + 1]
        if a["commit_id"] != b["commit_id"] or {a["target"], b["target"]} != {0, 1}:
            stats["pv_drop_structure"] += 1
            continue
        vr, sr = (a, b) if a["target"] == 1 else (b, a)
        vc, sc = vr["func"].strip(), sr["func"].strip()
        if not all(MIN_CHARS <= len(c) <= MAX_CHARS for c in (vc, sc)):
            stats["pv_drop_length"] += 1
            continue
        hv, hs = code_hash(vc), code_hash(sc)
        cve = (vr.get("cve") or "").strip()
        if hv == hs or hv in seen or hs in seen:
            stats["pv_drop_dup"] += 1
            continue
        if (cve and cve in our_cves) or hv in our_hashes or hs in our_hashes:
            stats["pv_drop_leak"] += 1
            continue
        cwe = vr.get("cwe") or []
        cwe_id = (cwe[0] if isinstance(cwe, list) and cwe else str(cwe)).strip()
        if not cwe_id.startswith("CWE-"):
            stats["pv_drop_no_cwe"] += 1
            continue
        seen.add(hv); seen.add(hs)
        ext = str(vr.get("file_name") or "").rsplit(".", 1)[-1].lower()
        lang = "C++" if ext in CPP_EXTS else "C"
        sev, cvss = derive_severity(None, "")
        reason = extract_reason(vr.get("cve_desc") or "", "") or f"Vulnerability classified as {cwe_id}."
        pid = f"pv_{vr['commit_id'][:12]}_{vr['idx']}"
        meta = {"cve_id": cve, "language": lang, "lang_group": LANG_GROUP[lang],
                "cwe_id": cwe_id, "severity": sev, "published_date": "", "source": "primevul"}
        out.append({"prompt": PROMPT_TMPL.format(language=lang, code=vc),
                    "completion": vuln_completion(cwe_id, "", sev, cvss, reason),
                    "meta": {**meta, "pair_id": pid, "label": "vuln"}})
        out.append({"prompt": PROMPT_TMPL.format(language=lang, code=sc),
                    "completion": SAFE_COMPLETION,
                    "meta": {**meta, "pair_id": pid, "label": "safe"}})
        stats["pv_keep_pairs"] += 1
    print(f"[PrimeVul] {stats['pv_keep_pairs']}쌍 편입")
    return out


def load_cleanvul(our_hashes, seen, stats) -> list[dict]:
    """safe-only hard-negative. 시간분할 오래된 70%만."""
    rows = [r for r in csv.DictReader((RAW / "cleanvul_score4.csv").open()) if r.get("date")]
    rows.sort(key=lambda r: r["date"])
    train_rows = rows[:int(len(rows) * CLEANVUL_TRAIN_FRAC)]
    out: list[dict] = []
    for r in train_rows:
        lang = EXT_LANG.get((r.get("extension") or "").strip().lower())
        if lang is None:
            stats["cv_drop_language"] += 1
            continue
        sc = (r.get("func_after") or "").strip()
        if not (MIN_CHARS <= len(sc) <= MAX_CHARS):
            stats["cv_drop_length"] += 1
            continue
        h = code_hash(sc)
        if h in seen or h in our_hashes:
            stats["cv_drop_dup_or_leak"] += 1
            continue
        seen.add(h)
        out.append({"prompt": PROMPT_TMPL.format(language=lang, code=sc),
                    "completion": SAFE_COMPLETION,
                    "meta": {"cve_id": (r.get("cve_id") or "").strip(), "language": lang,
                             "lang_group": LANG_GROUP[lang], "cwe_id": "", "severity": "NONE",
                             "published_date": r.get("date", ""), "source": "cleanvul",
                             "pair_id": None, "label": "safe"}})
    print(f"[CleanVul] safe-only {len(out)}건 (시간분할 70% 내)")
    return out


# ── val 층화 선택 ────────────────────────────────────────────────────────────
def pick_val(paired_groups: dict[str, list[dict]], cleanvul_groups: dict[str, list[dict]],
             n_total: int, rng: random.Random) -> set[str]:
    """
    val = 10%. 라벨 목표 vuln 46% / safe 54%.
    쌍 그룹(vuln+safe 동수)으로 vuln 46% + safe 46%를 채우고,
    남는 8%를 CleanVul safe-only로 채운다 → 정확히 목표 비율.
    언어는 내부 test 분포를 목표로 비례 배분(공급 부족 언어는 있는 만큼만).
    """
    n_val = int(n_total * VAL_FRAC)
    n_from_pairs = int(n_val * VAL_VULN_TARGET * 2)      # vuln+safe 동수
    n_from_cleanvul = n_val - n_from_pairs

    test_lang = Counter(json.loads(l)["meta"]["lang_group"] for l in (DATA / "test.jsonl").open())
    total_test = sum(test_lang.values())

    by_lang: dict[str, list[str]] = defaultdict(list)
    for k, items in paired_groups.items():
        by_lang[items[0]["meta"]["lang_group"]].append(k)
    for keys in by_lang.values():
        keys.sort(); rng.shuffle(keys)

    chosen: set[str] = set()
    taken = 0
    # 1순위: 내부 test 언어 비율대로
    for lang, cnt in sorted(test_lang.items(), key=lambda x: -x[1]):
        quota = int(n_from_pairs * cnt / total_test)
        for k in by_lang.get(lang, []):
            if quota <= 0:
                break
            chosen.add(k); n = len(paired_groups[k]); quota -= n; taken += n
    # 2순위: 목표 미달분은 공급 있는 언어에서 아무거나 채움
    if taken < n_from_pairs:
        rest = [k for keys in by_lang.values() for k in keys if k not in chosen]
        rng.shuffle(rest)
        for k in rest:
            if taken >= n_from_pairs:
                break
            chosen.add(k); taken += len(paired_groups[k])

    cv_keys = sorted(cleanvul_groups)
    rng.shuffle(cv_keys)
    cv_taken = 0
    for k in cv_keys:
        if cv_taken >= n_from_cleanvul:
            break
        chosen.add(k); cv_taken += len(cleanvul_groups[k])
    print(f"[val 설계] 목표 {n_val}건 = 쌍 {taken} + CleanVul {cv_taken}")
    return chosen


# ── 통계 ─────────────────────────────────────────────────────────────────────
def cross_tab(items: list[dict]) -> dict:
    tab: dict = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    for s in items:
        m = s["meta"]
        tab[m["source"]][m["label"]][m["lang_group"]] += 1
    c = Counter(s["meta"]["label"] for s in items)
    n = len(items)
    return {
        "n": n,
        "label": {"vuln": c["vuln"], "safe": c["safe"],
                  "vuln_frac": round(c["vuln"] / n, 4) if n else 0,
                  "safe_frac": round(c["safe"] / n, 4) if n else 0},
        "language": dict(Counter(s["meta"]["lang_group"] for s in items)),
        "source": dict(Counter(s["meta"]["source"] for s in items)),
        "source_x_label_x_language": {s: {l: dict(g) for l, g in d.items()} for s, d in tab.items()},
    }


def main() -> None:
    rng = random.Random(SEED)
    our_cves, our_hashes = existing_fingerprints()
    seen: set[str] = set()
    stats = Counter()

    base = load_base(seen)
    pv = load_primevul(our_cves, our_hashes, seen, stats)
    cv = load_cleanvul(our_hashes, seen, stats)

    # ── 소스 상한: CleanVul safe-only가 라벨을 SAFE로 왜곡하지 않게 컷 ──
    paired = base + pv
    n_vuln = sum(1 for s in paired if s["meta"]["label"] == "vuln")
    # (n_vuln) / (len(paired) + k) >= MIN_TRAIN_VULN_FRAC  →  k 상한
    max_cv = max(0, int(n_vuln / MIN_TRAIN_VULN_FRAC) - len(paired))
    rng.shuffle(cv)
    dropped = len(cv) - min(len(cv), max_cv)
    cv = cv[:max_cv]
    print(f"[상한] CleanVul {len(cv)}건 유지 / {dropped}건 제외 "
          f"(vuln 비율 하한 {MIN_TRAIN_VULN_FRAC} 유지)")
    stats["cv_capped_out"] = dropped

    all_samples = paired + cv
    groups: dict[str, list[dict]] = defaultdict(list)
    for s in all_samples:
        groups[group_key(s)].append(s)
    print(f"총 {len(all_samples)}건 / 그룹 {len(groups)}개 "
          f"(최대 그룹 크기 {max(len(v) for v in groups.values())})")

    paired_groups = {k: v for k, v in groups.items() if v[0]["meta"]["source"] != "cleanvul"}
    cleanvul_groups = {k: v for k, v in groups.items() if v[0]["meta"]["source"] == "cleanvul"}
    val_keys = pick_val(paired_groups, cleanvul_groups, len(all_samples), rng)

    splits = {"train_v3": [], "val_v3": []}
    for k, items in groups.items():
        splits["val_v3" if k in val_keys else "train_v3"].extend(items)

    out_stats = {"seed": SEED, "loader_stats": dict(stats), "splits": {}}
    for name, items in splits.items():
        rng.shuffle(items)
        with (DATA / f"{name}.jsonl").open("w") as f:
            for s in items:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        out_stats["splits"][name] = cross_tab(items)
        st = out_stats["splits"][name]
        print(f"\n=== {name}: {st['n']}건 vuln {st['label']['vuln']} "
              f"({st['label']['vuln_frac']:.3f}) / safe {st['label']['safe']}")
        print("  언어:", st["language"], "\n  소스:", st["source"])

    # 참고용: 내부 test 분포도 같이 저장 (val이 test를 얼마나 닮았는지 대조)
    test_rows = [json.loads(l) for l in (DATA / "test.jsonl").open()]
    for r in test_rows:
        r["meta"].setdefault("source", "cvefixes")
    out_stats["reference_internal_test"] = cross_tab(test_rows)

    # ── 게이트 (사양서 §4): 위반 시 학습 금지 ──
    v = out_stats["splits"]["val_v3"]["label"]
    gate_ok = v["safe_frac"] <= 0.60 and v["vuln_frac"] >= 0.35
    out_stats["gate"] = {"val_safe_frac": v["safe_frac"], "val_vuln_frac": v["vuln_frac"],
                         "passed": gate_ok,
                         "rule": "val safe<=0.60 and vuln>=0.35"}
    (ROOT / "out" / "v3_data_stats.json").write_text(json.dumps(out_stats, ensure_ascii=False, indent=2))
    print(f"\n게이트: {'통과' if gate_ok else '실패'} "
          f"(val safe {v['safe_frac']:.3f} / vuln {v['vuln_frac']:.3f})")
    if not gate_ok:
        raise SystemExit("게이트 실패 — 학습 시작 금지")


if __name__ == "__main__":
    main()
