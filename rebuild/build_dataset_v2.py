"""
ScanOps 재구축 — v2 학습 데이터 빌더 (데이터 확장)
====================================================
v1(build_dataset.py, CVEfixes 단일 분포)의 약점을 데이터로 처방한다:
  - 교차분포 재현율 급락 (PrimeVul C/C++ 12.8%) → PrimeVul train 쌍 편입
  - JS/TS 오탐 65% → JS/TS 쌍 오버샘플링 + CleanVul hard-negative

핵심 원칙 (노션 v2 계획):
  1. 내부 test(1,197건)는 절대 안 건드림 — v1과 같은 자로 비교하기 위함.
     새 학습 데이터는 기존 train/val/test 3종의 (CVE ID + 코드 해시)로 dedup.
  2. pair_id로 쌍을 추적(관리용, 모델은 안 봄). 고아 샘플도 학습엔 유지(신호 유효).
  3. JS/TS 완전 쌍만 2배 오버샘플링 (오탐 처방 — 검증 유무 대비 신호 강화).

편입 소스:
  - v1 train/val (CVEfixes)          : 그대로 (이미 dedup·포맷 완료)
  - PrimeVul train_paired (3,789쌍)  : C/C++, CWE 있음 → 취약/안전 쌍 완전 편입
  - CleanVul score-4 (안전본만)       : CWE 없어 취약본 불가 → func_after=hard-negative만
                                        시간 분할: 오래된 70%만 학습, 최신 30%는 held-out(평가 별도)

completion 생성: build_dataset.py의 로직 재사용(derive_severity/extract_reason).
  PrimeVul은 CVSS 없음 → SEVERITY/CVSS UNKNOWN, REASON은 cve_desc에서 추출.

출력: rebuild/data/train_v2.jsonl, val_v2.jsonl  (test는 기존 test.jsonl 그대로 씀)
      rebuild/data/cleanvul_heldout.jsonl  (CleanVul 최신 30% — v2 외부평가용)
실행: .venv/bin/python rebuild/build_dataset_v2.py
"""
from __future__ import annotations

import csv
import hashlib
import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

# v1 빌더의 completion 로직을 그대로 재사용 (중복 구현 방지)
from build_dataset import (
    LANG_GROUP, MAX_CHARS, MIN_CHARS, PROMPT_TMPL, SAFE_COMPLETION,
    derive_severity, extract_reason, vuln_completion,
)

SEED = 42
ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
RAW = DATA / "raw"

EXT_LANG = {"c": "C", "cpp": "C++", "java": "Java", "js": "JavaScript", "py": "Python"}
CPP_EXTS = {"cc", "cpp", "cxx", "hpp", "hh", "c++"}
CLEANVUL_TRAIN_FRAC = 0.70   # 시간 분할: 오래된 70% 학습, 최신 30% held-out


def code_hash(code: str) -> str:
    return hashlib.sha1(re.sub(r"\s+", " ", code).strip().lower().encode()).hexdigest()


def code_fence(prompt: str) -> str:
    m = re.search(r"```[^\n]*\n(.*?)\n```", prompt, re.S)
    return m.group(1) if m else ""


# ── 기존 3종(train/val/test)의 지문 — 누수 제거 대조군 ────────────────────────
def existing_fingerprints() -> tuple[set[str], set[str]]:
    cves: set[str] = set()
    hashes: set[str] = set()
    # 평가에 쓸 test 3종을 전부 대조군에 — v2 학습이 어떤 평가셋도 오염시키면 안 됨.
    # (내부 test + PrimeVul paired test + CleanVul held-out. PrimeVul은 train/test가
    #  같은 CVE를 공유하는 경우가 있어 반드시 test까지 걸러야 누수 차단됨.)
    eval_files = ["test", "primevul_test", "cleanvul_v2_test"]
    for split in ["train", "val"] + eval_files:
        path = DATA / f"{split}.jsonl"
        if not path.exists():           # cleanvul_v2_test는 첫 빌드 땐 없을 수 있음(1회차엔 스킵)
            continue
        for row in (json.loads(l) for l in path.open()):
            cves.add(row["meta"].get("cve_id", ""))
            h = code_hash(code_fence(row["prompt"]))
            if h:
                hashes.add(h)
    cves.discard("")
    print(f"대조군(train+val+평가 3종): CVE {len(cves)} / 해시 {len(hashes)}")
    return cves, hashes


# ── PrimeVul train_paired → 취약/안전 쌍 샘플 ────────────────────────────────
def load_primevul(our_cves, our_hashes, seen, stats) -> list[dict]:
    rows = [json.loads(l) for l in (RAW / "primevul_train_paired.jsonl").open()]
    out: list[dict] = []
    for i in range(0, len(rows) - 1, 2):
        a, b = rows[i], rows[i + 1]
        if a["commit_id"] != b["commit_id"] or {a["target"], b["target"]} != {0, 1}:
            stats["pv_drop_structure"] += 1
            continue
        vr = a if a["target"] == 1 else b
        sr = b if a["target"] == 1 else a
        vc, sc = vr["func"].strip(), sr["func"].strip()

        # 길이 필터 + 쌍 dedup (한쪽이라도 걸리면 쌍 전체 제외 — 쌍 보존)
        if not all(MIN_CHARS <= len(c) <= MAX_CHARS for c in (vc, sc)):
            stats["pv_drop_length"] += 1
            continue
        hv, hs = code_hash(vc), code_hash(sc)
        cve = (vr.get("cve") or "").strip()
        if hv == hs or hv in seen or hs in seen:
            stats["pv_drop_dup"] += 1
            continue
        if (cve and cve in our_cves) or hv in our_hashes or hs in our_hashes:
            stats["pv_drop_leak"] += 1     # 기존 3종과 겹치면 누수 → 제외
            continue
        seen.add(hv); seen.add(hs)

        ext = str(vr.get("file_name") or "").rsplit(".", 1)[-1].lower()
        lang = "C++" if ext in CPP_EXTS else "C"
        cwe = vr.get("cwe") or []
        cwe_id = (cwe[0] if isinstance(cwe, list) and cwe else str(cwe)).strip()
        if not cwe_id.startswith("CWE-"):
            stats["pv_drop_no_cwe"] += 1
            continue
        # PrimeVul엔 CVSS/severity 없음 → UNKNOWN. REASON은 cve_desc에서.
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
    print(f"[PrimeVul] {stats['pv_keep_pairs']}쌍 편입 / {dict((k,v) for k,v in stats.items() if k.startswith('pv_'))}")
    return out


# ── CleanVul → 안전본(func_after)만 = hard-negative. 시간분할 70% 학습 ────────
def load_cleanvul(our_cves, our_hashes, seen, stats) -> tuple[list[dict], list[dict]]:
    rows = [r for r in csv.DictReader((RAW / "cleanvul_score4.csv").open()) if r.get("date")]
    rows.sort(key=lambda r: r["date"])           # 오래된 → 최신
    cut = int(len(rows) * CLEANVUL_TRAIN_FRAC)
    train_rows, held_rows = rows[:cut], rows[cut:]

    train_out: list[dict] = []
    for r in train_rows:
        lang = EXT_LANG.get((r.get("extension") or "").strip().lower())
        if lang is None:
            stats["cv_drop_language"] += 1
            continue
        sc = (r.get("func_after") or "").strip()   # ★ 안전본만 — 취약본은 CWE 없어 불가
        if not (MIN_CHARS <= len(sc) <= MAX_CHARS):
            stats["cv_drop_length"] += 1
            continue
        hs = code_hash(sc)
        if hs in seen or hs in our_hashes:
            stats["cv_drop_dup_or_leak"] += 1
            continue
        seen.add(hs)
        train_out.append({
            "prompt": PROMPT_TMPL.format(language=lang, code=sc),
            "completion": SAFE_COMPLETION,
            "meta": {"cve_id": (r.get("cve_id") or "").strip(), "language": lang,
                     "lang_group": LANG_GROUP[lang], "cwe_id": "", "severity": "NONE",
                     "published_date": r.get("date", ""), "source": "cleanvul",
                     "pair_id": None, "label": "safe"},
        })
        stats["cv_keep_safe"] += 1

    print(f"[CleanVul] 안전본 {stats['cv_keep_safe']}건 학습 편입 (시간분할 70%) / held-out {len(held_rows)}행")
    print(f"  {dict((k,v) for k,v in stats.items() if k.startswith('cv_'))}")
    return train_out, held_rows   # held_rows는 나중에 build_external_bench 방식으로 평가셋화


# ── JS/TS 완전 쌍 오버샘플링 ─────────────────────────────────────────────────
def oversample_jsts(samples: list[dict]) -> list[dict]:
    """JS/TS이면서 pair_id가 완전 쌍(vuln+safe 둘 다 존재)인 샘플을 2배로."""
    pair_labels: dict[str, set] = defaultdict(set)
    for s in samples:
        pid = s["meta"].get("pair_id")
        if pid:
            pair_labels[pid].add(s["meta"]["label"])
    complete = {pid for pid, labs in pair_labels.items() if labs == {"vuln", "safe"}}
    extra = [s for s in samples
             if s["meta"]["lang_group"] == "JS/TS" and s["meta"].get("pair_id") in complete]
    print(f"[오버샘플링] JS/TS 완전 쌍 샘플 {len(extra)}건 복제 추가")
    return samples + extra


def main() -> None:
    random.seed(SEED)
    our_cves, our_hashes = existing_fingerprints()
    seen: set[str] = set()
    stats = Counter()

    # v1 train/val 로드 (이미 포맷 완료 — pair_id 없으니 채워줌)
    base: list[dict] = []
    for split in ("train", "val"):
        for row in (json.loads(l) for l in (DATA / f"{split}.jsonl").open()):
            row["meta"].setdefault("pair_id", f"cvefixes_{row['meta']['cve_id']}")
            row["meta"].setdefault("source", "cvefixes")
            base.append(row)
            seen.add(code_hash(code_fence(row["prompt"])))
    print(f"v1 base(train+val): {len(base)}건")

    pv = load_primevul(our_cves, our_hashes, seen, stats)
    cv_train, cv_held = load_cleanvul(our_cves, our_hashes, seen, stats)

    combined = oversample_jsts(base + pv + cv_train)

    # train/val 재분할: cve_id(또는 pair_id) 그룹 단위로 셔플 후 90/10
    random.shuffle(combined)
    groups = defaultdict(list)
    for s in combined:
        groups[s["meta"].get("pair_id") or s["meta"]["cve_id"]].append(s)
    keys = list(groups); random.shuffle(keys)
    n_val = max(1, len(keys) // 10)
    val_keys = set(keys[:n_val])

    splits = {"train_v2": [], "val_v2": []}
    for k, items in groups.items():
        splits["val_v2" if k in val_keys else "train_v2"].extend(items)

    for name, items in splits.items():
        random.shuffle(items)
        path = DATA / f"{name}.jsonl"
        with path.open("w") as f:
            for s in items:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        c = Counter(s["meta"]["label"] for s in items)
        print(f"\n=== {name}: {len(items)}건 (vuln {c['vuln']} / safe {c['safe']}) → {path}")
        print("  언어:", dict(Counter(s["meta"]["lang_group"] for s in items)))
        print("  소스:", dict(Counter(s["meta"]["source"] for s in items)))

    # CleanVul held-out 원본 행 저장 (다음 단계에서 평가셋으로 변환)
    (DATA / "cleanvul_heldout_raw.json").write_text(json.dumps(cv_held, ensure_ascii=False))
    print(f"\nCleanVul held-out 원본 {len(cv_held)}행 → data/cleanvul_heldout_raw.json")


if __name__ == "__main__":
    main()
