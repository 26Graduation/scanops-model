"""
ScanOps 재구축 — 외부 벤치마크 빌더 (PrimeVul paired + CleanVul)
=================================================================
왜 하나: 내부 test(CVEfixes)만으로는 "우리 데이터로 우리 모델을 채점했다"는
반박을 못 막는다. 학습 분포 밖의 공개 벤치마크 2개에서 같은 프롬프트·같은
채점으로 우리 모델 vs Claude를 재비교한다.

  PrimeVul paired test (arXiv:2403.18624)
    - C/C++ 전용, 435쌍(취약/패치) = 870건. 사람이 검수한 엄격한 쌍 세트.
    - 쌍 단위 채점(P-C 등)이 논문 공식 프로토콜 → 우리 "패치 전후 구분" 서사와 일치.
  CleanVul score-4 (arXiv:2411.17274)
    - fix 커밋 라벨 노이즈를 LLM으로 걸러낸 고신뢰(≈97%) 세트. func_before/after 쌍.
    - Java 표본이 커서 내부 test의 Java 부족(69건)을 보완. 단 PHP는 없음(각주 처리).

파이프라인:
  ① HuggingFace에서 원본 다운로드 → data/raw/ 캐시
  ② 언어 필터 (우리 5개 언어 그룹에 드는 것만; CleanVul의 C#는 제외)
  ③ 각 쌍을 취약/안전 샘플로 전개 + 길이 필터(내부 test와 동일: 40자~12,000자)
  ④ 누수 제거(dedup) — 우리 train/val과의 겹침을 두 기준으로 제거:
       (a) CVE ID 겹침       — 같은 CVE에서 나온 샘플
       (b) 정규화 코드 해시 겹침 — CVE ID가 달라도 같은 함수 (build_dataset.py와 동일 해시)
     한쪽이라도 걸리면 "쌍 전체"를 제거(쌍 단위 채점 보전). 기준별 제거 건수를 보고.
  ⑤ 내부 test와 동일한 PROMPT_TMPL로 포맷 → data/{primevul,cleanvul}_test.jsonl

출력 형식: {"prompt", "meta": {source, pair_id, label, language, lang_group,
            cve_id, cwe_id, ...}}  (completion 없음 — 평가 전용이라 불필요)

실행:  .venv/bin/python rebuild/build_external_bench.py     (로컬, GPU 불필요)
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
RAW = DATA / "raw"

HF = "https://huggingface.co/datasets"
SOURCES = {
    "primevul": (f"{HF}/starsofchance/PrimeVul/resolve/main/primevul_test_paired.jsonl",
                 RAW / "primevul_test_paired.jsonl"),
    "cleanvul": (f"{HF}/yikun-li/CleanVul/resolve/main/vulnerability_score_4.csv",
                 RAW / "cleanvul_score4.csv"),
}

# 내부 test와 동일한 길이 필터·프롬프트 (build_dataset.py에서 그대로)
MIN_CHARS, MAX_CHARS = 40, 12_000
PROMPT_TMPL = """Analyze the following {language} code for security vulnerabilities.

```{language}
{code}
```

Respond in exactly this format:
VULNERABILITY: <CWE-id (CWE name)> or NONE
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN> or NONE
CVSS: <score 0.0-10.0> or 0.0
REASON: <one-line explanation> or NONE"""

LANG_GROUP = {
    "Python": "Python", "JavaScript": "JS/TS", "TypeScript": "JS/TS",
    "Java": "Java", "PHP": "PHP", "C": "C/C++", "C++": "C/C++",
}
# CleanVul의 extension → 언어. 여기 없는 확장자(cs 등)는 5개 언어 밖이라 제외.
EXT_LANG = {"c": "C", "cpp": "C++", "java": "Java", "js": "JavaScript", "py": "Python"}
# PrimeVul(전부 C/C++)의 파일 확장자 → C vs C++ 구분 (프롬프트의 {language} 표기용)
CPP_EXTS = {"cc", "cpp", "cxx", "hpp", "hh", "c++"}


def code_hash(code: str) -> str:
    """build_dataset.py와 동일한 정규화 해시 — dedup 기준 (b)의 키."""
    normalized = re.sub(r"\s+", " ", code).strip().lower()
    return hashlib.sha1(normalized.encode()).hexdigest()


def download(url: str, dest: Path) -> None:
    if dest.exists():
        print(f"  캐시 사용: {dest.name}")
        return
    print(f"  다운로드: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    dest.write_bytes(urllib.request.urlopen(req, timeout=300).read())


# ── 우리 train/val의 CVE ID·코드 해시 수집 (dedup 대조군) ─────────────────────
CODE_FENCE = re.compile(r"```[^\n]*\n(.*?)\n```", re.S)

def load_train_fingerprints() -> tuple[set[str], set[str]]:
    """학습에 쓰인(train+val) 샘플들의 (CVE ID 집합, 정규화 코드 해시 집합).
    test.jsonl은 학습에 안 쓰였으므로 대조군에서 제외 — 여기 겹쳐도 누수가 아님."""
    cves: set[str] = set()
    hashes: set[str] = set()
    for split in ("train", "val"):
        for row in (json.loads(l) for l in (DATA / f"{split}.jsonl").open()):
            cves.add(row["meta"]["cve_id"])
            m = CODE_FENCE.search(row["prompt"])   # prompt 안의 코드만 추출해 해시
            if m:
                hashes.add(code_hash(m.group(1)))
    print(f"대조군(train+val): CVE {len(cves)}개 / 코드 해시 {len(hashes)}개")
    return cves, hashes


# ── 쌍 필터: 길이 → 자기중복 → 누수(dedup) 순서로 검사, 통계 기록 ─────────────
def keep_pair(vuln_code: str, safe_code: str, cve_id: str,
              our_cves: set[str], our_hashes: set[str],
              seen: set[str], stats: Counter) -> bool:
    for code in (vuln_code, safe_code):
        if not (MIN_CHARS <= len(code) <= MAX_CHARS):
            stats["drop_pair_length"] += 1
            return False
    hv, hs = code_hash(vuln_code), code_hash(safe_code)
    if hv == hs:                                  # 취약본==패치본이면 라벨이 성립 안 함
        stats["drop_pair_identical"] += 1
        return False
    if hv in seen or hs in seen:                  # 벤치마크 내부 중복
        stats["drop_pair_dup_in_bench"] += 1
        return False
    # ── 누수 제거 (a): CVE ID 겹침 ──
    if cve_id and cve_id in our_cves:
        stats["drop_pair_leak_cve"] += 1
        return False
    # ── 누수 제거 (b): 정규화 코드 해시 겹침 ──
    if hv in our_hashes or hs in our_hashes:
        stats["drop_pair_leak_hash"] += 1
        return False
    seen.add(hv); seen.add(hs)
    return True


def emit_pair(out: list[dict], pair_id: str, language: str,
              vuln_code: str, safe_code: str, meta_common: dict) -> None:
    for code, label in ((vuln_code, "vuln"), (safe_code, "safe")):
        out.append({
            "prompt": PROMPT_TMPL.format(language=language, code=code),
            "meta": {**meta_common, "pair_id": pair_id, "label": label,
                     "language": language, "lang_group": LANG_GROUP[language]},
        })


# ── PrimeVul paired test 빌드 ────────────────────────────────────────────────
def build_primevul(our_cves: set[str], our_hashes: set[str]) -> list[dict]:
    rows = [json.loads(l) for l in SOURCES["primevul"][1].open()]
    out: list[dict] = []
    seen: set[str] = set()
    stats = Counter(pairs_total=len(rows) // 2)

    # 파일 구조: 연속된 두 행이 한 쌍 (target=1 취약본, target=0 패치본, 같은 commit_id)
    for i in range(0, len(rows) - 1, 2):
        a, b = rows[i], rows[i + 1]
        if a["commit_id"] != b["commit_id"] or {a["target"], b["target"]} != {0, 1}:
            stats["drop_pair_structure"] += 1     # 구조가 깨진 쌍(없어야 정상)
            continue
        vuln_row = a if a["target"] == 1 else b
        safe_row = b if a["target"] == 1 else a

        ext = str(vuln_row.get("file_name") or "").rsplit(".", 1)[-1].lower()
        language = "C++" if ext in CPP_EXTS else "C"
        cve_id = (vuln_row.get("cve") or "").strip()
        cwe = vuln_row.get("cwe") or []           # 원본은 리스트(예: ['CWE-704'])
        cwe_id = (cwe[0] if isinstance(cwe, list) and cwe else str(cwe)).strip()

        vc, sc = vuln_row["func"].strip(), safe_row["func"].strip()
        if not keep_pair(vc, sc, cve_id, our_cves, our_hashes, seen, stats):
            continue
        emit_pair(out, pair_id=f"pv_{vuln_row['commit_id'][:12]}_{vuln_row['idx']}",
                  language=language, vuln_code=vc, safe_code=sc,
                  meta_common={"source": "primevul", "cve_id": cve_id, "cwe_id": cwe_id,
                               "commit_id": vuln_row["commit_id"], "project": vuln_row.get("project", "")})
        stats["keep_pairs"] += 1

    print(f"\n[PrimeVul] {stats['keep_pairs']}쌍 = {len(out)}건 유지 / 통계: {dict(stats)}")
    return out


# ── CleanVul score-4 빌드 ────────────────────────────────────────────────────
def build_cleanvul(our_cves: set[str], our_hashes: set[str]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    stats = Counter()

    with SOURCES["cleanvul"][1].open() as f:
        for i, row in enumerate(csv.DictReader(f)):
            stats["rows_total"] += 1
            language = EXT_LANG.get((row.get("extension") or "").strip().lower())
            if language is None:                  # C# 등 5개 언어 밖 → 제외
                stats["drop_language"] += 1
                continue
            cve_id = (row.get("cve_id") or "").strip()   # 대부분 결측 → (b) 해시 dedup이 주력
            vc, sc = (row.get("func_before") or "").strip(), (row.get("func_after") or "").strip()
            if not keep_pair(vc, sc, cve_id, our_cves, our_hashes, seen, stats):
                continue
            emit_pair(out, pair_id=f"cv_{i}", language=language,
                      vuln_code=vc, safe_code=sc,
                      meta_common={"source": "cleanvul", "cve_id": cve_id,
                                   "cwe_id": (row.get("cwe_id") or "").strip(),
                                   "commit_url": (row.get("commit_url") or "").strip(),
                                   "date": (row.get("date") or "").strip()})
            stats["keep_pairs"] += 1

    print(f"\n[CleanVul] {stats['keep_pairs']}쌍 = {len(out)}건 유지 / 통계: {dict(stats)}")
    return out


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    for url, dest in SOURCES.values():
        download(url, dest)

    our_cves, our_hashes = load_train_fingerprints()

    for name, samples in (("primevul", build_primevul(our_cves, our_hashes)),
                          ("cleanvul", build_cleanvul(our_cves, our_hashes))):
        path = DATA / f"{name}_test.jsonl"
        with path.open("w") as f:
            for s in samples:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        print(f"=== {name}: {len(samples)}건 → {path}")
        print("  라벨:", dict(Counter(s["meta"]["label"] for s in samples)))
        print("  언어:", dict(Counter(s["meta"]["lang_group"] for s in samples)))


if __name__ == "__main__":
    main()
