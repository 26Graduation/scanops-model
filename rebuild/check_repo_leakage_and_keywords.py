"""
레포 단위 누수 체크 + security_keywords 빈 배열 비율 체크
==========================================================
build_dataset.py와 동일한 필터링(언어/CWE/길이/dedup)과 동일한 시간분할 로직을
그대로 재현해서, 다음 두 가지를 확인합니다.

1. security_keywords가 실제로 몇 %나 비어있는지 (원본 전체 행 기준)
2. 같은 repo_url이 test CVE 그룹과 train/val CVE 그룹에 걸쳐 나타나는지
   (CVE 단위 분할로는 못 막는, repo 단위의 약한 누수 가능성 체크)

실행 방법: build_dataset.py를 돌렸던 것과 같은 환경(datasets 라이브러리 설치돼
있고 HuggingFace 접속 가능한 곳 — 로컬 venv 또는 RunPod 팟)에서:

    python check_repo_leakage_and_keywords.py

주의: 13k행 스트리밍이라 몇 분 정도 걸릴 수 있습니다.
"""
import re, hashlib, json
from collections import Counter, defaultdict

from datasets import load_dataset

LANG_MAP = {
    "python": "Python",
    "javascript": "JavaScript", "typescript": "TypeScript",
    "java": "Java",
    "php": "PHP",
    "c": "C", "c++": "C++", "cpp": "C++",
}
MIN_CHARS, MAX_CHARS = 40, 12_000

def code_hash(code):
    normalized = re.sub(r"\s+", " ", code).strip().lower()
    return hashlib.sha1(normalized.encode()).hexdigest()

print("Loading hitoshura25/cvefixes (streaming)...", flush=True)
ds = load_dataset("hitoshura25/cvefixes", split="train", streaming=True)

samples = []  # each: cve_id, repo_url, published_date
seen_hashes = set()
stats = Counter()

sec_kw_empty = 0
sec_kw_total_seen = 0
sec_kw_field_present = 0

repo_url_col_candidates = None

for i, row in enumerate(ds):
    stats["rows_total"] += 1

    # security_keywords stat over ALL raw rows (before any filtering)
    if "security_keywords" in row:
        sec_kw_field_present += 1
        val = row.get("security_keywords")
        sec_kw_total_seen += 1
        # could be list, or stringified list, or None
        is_empty = False
        if val is None:
            is_empty = True
        elif isinstance(val, (list, tuple)):
            is_empty = len(val) == 0
        elif isinstance(val, str):
            s = val.strip()
            is_empty = s in ("", "[]", "None")
        if is_empty:
            sec_kw_empty += 1

    lang = LANG_MAP.get(str(row.get("language") or "").strip().lower())
    if lang is None:
        stats["drop_language"] += 1
        continue

    cve_id = (row.get("cve_id") or "").strip()
    cwe_id = (row.get("cwe_id") or "").strip()
    if not cve_id or not cwe_id.startswith("CWE-"):
        stats["drop_no_cwe"] += 1
        continue

    repo_url = (row.get("repo_url") or "").strip()
    pub = (row.get("published_date") or "").strip()

    for code, label in ((row.get("vulnerable_code"), "vuln"), (row.get("fixed_code"), "safe")):
        code = (code or "").strip()
        if not (MIN_CHARS <= len(code) <= MAX_CHARS):
            stats[f"drop_length_{label}"] += 1
            continue
        h = code_hash(code)
        if h in seen_hashes:
            stats["drop_dup"] += 1
            continue
        seen_hashes.add(h)
        samples.append({"cve_id": cve_id, "repo_url": repo_url, "published_date": pub, "label": label})
        stats[f"keep_{label}"] += 1

    if i % 2000 == 0:
        print(f"...{i} rows processed", flush=True)

print("\n=== FILTER STATS ===")
print(dict(stats))

print(f"\n=== security_keywords ===")
print(f"raw rows with field present: {sec_kw_field_present} / {stats['rows_total']}")
print(f"empty (None/[]/'') count: {sec_kw_empty} / {sec_kw_total_seen} = {sec_kw_empty/max(sec_kw_total_seen,1)*100:.1f}%")

# Now replicate the time split
pub_by_cve = {}
for s in samples:
    c = s["cve_id"]
    pub_by_cve[c] = max(pub_by_cve.get(c, ""), s["published_date"])
cves_sorted = sorted(pub_by_cve, key=lambda c: pub_by_cve[c])
n_test = max(1, len(cves_sorted)//10)
test_cves = set(cves_sorted[-n_test:])
rest = [c for c in cves_sorted if c not in test_cves]

# repo -> set of cves (using repo_url per sample)
repo_to_cves = defaultdict(set)
cve_to_repos = defaultdict(set)
for s in samples:
    if s["repo_url"]:
        repo_to_cves[s["repo_url"]].add(s["cve_id"])
        cve_to_repos[s["cve_id"]].add(s["repo_url"])

# find repos that have at least one CVE in test AND at least one CVE in rest(train/val)
leaked_repos = []
for repo, cves in repo_to_cves.items():
    in_test = cves & test_cves
    in_rest = cves & set(rest)
    if in_test and in_rest:
        leaked_repos.append((repo, in_test, in_rest))

print(f"\n=== REPO-LEVEL LEAKAGE CHECK ===")
print(f"total distinct repos (with repo_url set): {len(repo_to_cves)}")
print(f"total distinct CVEs: {len(cves_sorted)} (test={len(test_cves)}, train+val={len(rest)})")
print(f"repos with CVEs split across test AND train/val: {len(leaked_repos)}")
if leaked_repos:
    print("example (up to 5):")
    for repo, in_test, in_rest in leaked_repos[:5]:
        print(f"  repo={repo!r} test_cves={in_test} train/val_cves={list(in_rest)[:3]}")

# also: how many CVEs have empty repo_url
empty_repo_cves = sum(1 for c in cves_sorted if not cve_to_repos.get(c))
print(f"\nCVEs with no repo_url recorded: {empty_repo_cves} / {len(cves_sorted)}")

print("\nDONE")
