"""ScanOps V16 학습데이터 — 데이터 확장(PrimeVul) + V15 앙상블 증류 필터
================================================================
V15 결론: v13∨v14 OR 앙상블이 3벤치 평균 Grok 능가. 단 ①서빙 비용 2배(모델 2회)
②OWASP 재현율 약함 ③학습 데이터가 CVEfixes 편중(도메인 적응 의심).

★V16.0 결과 (2026-07-02, negative result — 4벤치 평균 F1 52.8 < V15 59.9):
  CVEfixes는 역대최고(F1 73.6)였으나 OWASP·CyberNative FPR 92~100%(전부 취약),
  DiverseVul 재현율 1.3%(전부 안전). 진단 = **출처 스타일이 라벨과 상관**:
  CyberNative는 취약쪽만, PrimeVul 안전은 unpaired만 넣어서 모델이 취약점 의미가
  아니라 "출처 지문 → 라벨" 지름길을 학습.
★V16.1 수정: **모든 출처에서 양쪽 클래스를, 단 같은 코드 쌍은 금지(row-disjoint)**.
  - CyberNative: 행을 번갈아 짝수행→rejected(취약), 홀수행→chosen(안전). 같은 행의
    두 면을 동시에 안 씀(V14 쌍학습 회피) + 출처-라벨 상관 제거.
  - PrimeVul: 안전 절반을 train_paired의 안전쪽(취약에 안 쓴 commit만)에서, 절반을
    unpaired에서 → "paired 스타일=취약" 지름길 차단.

V16 처방 (7B 유지 + 데이터확장 + 증류):
  A. **PrimeVul 추가** (HF ASSERT-KTH/PrimeVul) — 벤치 4종(OWASP·CVEfixes·
     CyberNative·DiverseVul)과 **다른 출처**의 실제 커밋 C/C++ 함수. 라벨 품질이
     BigVul/DiverseVul보다 높음. V13에 없던 C/C++ 커버 확보.
     ★V14 교훈(discrimination-pair는 보수화 부작용) 반영:
       - 취약 = train_paired의 **취약 쪽만** 사용 (안전 짝은 버림 → 쌍 학습 회피)
       - 안전 = train_unpaired 에서만 샘플
  B. **CyberNative 취약-only 소량 추가** — 주입 패턴 재현율 보강(OWASP 약점).
     V14처럼 chosen/rejected 쌍이 아니라 rejected(취약) 쪽만 → 보수화 회피.
  C. **V15 앙상블 증류 필터** (scripts/distill_v15_labels.py 산출 사용, 선택):
     - GT=안전인데 v14(고정밀 교사)가 취약 판정 → **라벨 노이즈 의심, 제외**
     - GT=취약은 전부 유지 (재현율 우선; v13/그래프가 놓친 hard positive가
       앙상블을 넘어서는 학습 재료)
     증류 파일 없으면 원 라벨 그대로 사용(동작엔 지장 없음).

★ DiverseVul은 **학습에 절대 넣지 않는다** — "완전 독립 벤치마크" 지위 유지.

누수 차단: 벤치 4종 코드해시 + OWASP 홀드아웃 + v13/v14 학습셋 전부 dedup.
PrimeVul은 CVEfixes 등 기존 셋을 흡수한 병합 데이터셋이므로 해시 dedup 필수.

실행 (2단계):
  1) python -m ml.build_dataset_v16 --stage candidates          # HF에서 후보 수집
  2) (선택) python scripts/distill_v15_labels.py                # 로컬 Ollama 증류
  3) python -m ml.build_dataset_v16 --stage build               # 최종 학습셋 생성
산출: data/lora_train_v16.jsonl + data/lora_train_v16_val.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.benchmark_qwen_rag import build_ft_user_prompt

SEED = 41
NONE_COMPLETION = "VULNERABILITY: NONE\nSEVERITY: NONE\nCVSS: 0.0"
MIN_LEN, MAX_LEN = 60, 2000
CANDIDATES = ROOT / "data" / "v16_candidates.jsonl"
DISTILL = ROOT / "data" / "v16_distill.jsonl"

_OWASP = ("HttpServletRequest", "HttpServletResponse", "BenchmarkTest", "org.owasp")
CYBER_LANG = {
    "python": "Python", "java": "Java", "javascript": "Node.js / Express", "php": "PHP",
    "ruby": "Ruby", "go": "Go", "c#": "C#", "c++": "C++", "swift": "Swift", "kotlin": "Kotlin",
}


def _norm(c): return re.sub(r"\s+", " ", c or "").strip().lower()
def _h(c): return hashlib.sha1(_norm(c).encode()).hexdigest()
def _is_owasp(c): return any(k in c for k in _OWASP)


def _extract_md(md):
    m = re.search(r"```[a-zA-Z+#0-9./]*\n(.*?)```", md or "", re.S)
    return (m.group(1) if m else (md or "")).strip()


def _cpp_or_c(code: str) -> str:
    return "C++" if re.search(r"::|std::|template\s*<|\bnew\s+\w|class\s+\w+\s*[:{]", code) else "C"


# PrimeVul cwe_description은 긴 문단 → completion 라벨용 짧은 이름으로 매핑.
CWE_NAMES = {
    "CWE-20": "Improper Input Validation", "CWE-22": "Path Traversal",
    "CWE-59": "Link Following", "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection", "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection", "CWE-94": "Code Injection",
    "CWE-119": "Buffer Overflow", "CWE-120": "Classic Buffer Overflow",
    "CWE-125": "Out-of-bounds Read", "CWE-787": "Out-of-bounds Write",
    "CWE-129": "Improper Array Index Validation", "CWE-131": "Incorrect Buffer Size Calculation",
    "CWE-189": "Numeric Error", "CWE-190": "Integer Overflow",
    "CWE-191": "Integer Underflow", "CWE-200": "Information Exposure",
    "CWE-252": "Unchecked Return Value", "CWE-254": "Security Feature Bypass",
    "CWE-264": "Improper Access Control", "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control", "CWE-287": "Improper Authentication",
    "CWE-310": "Cryptographic Issue", "CWE-311": "Missing Encryption",
    "CWE-352": "Cross-Site Request Forgery (CSRF)", "CWE-362": "Race Condition",
    "CWE-369": "Divide By Zero", "CWE-399": "Resource Management Error",
    "CWE-400": "Uncontrolled Resource Consumption", "CWE-401": "Memory Leak",
    "CWE-415": "Double Free", "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload", "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Unsafe Deserialization", "CWE-617": "Reachable Assertion",
    "CWE-704": "Incorrect Type Conversion", "CWE-772": "Missing Resource Release",
    "CWE-835": "Infinite Loop", "CWE-843": "Type Confusion",
    "CWE-908": "Use of Uninitialized Resource", "CWE-917": "Expression Language Injection",
}


def _cwe_name(cwes: list[str] | None) -> str:
    for c in cwes or []:
        c = c.strip().upper()
        if c in CWE_NAMES:
            return f"{CWE_NAMES[c]} ({c})"
    for c in cwes or []:
        c = c.strip().upper()
        if c.startswith("CWE-"):
            return f"{c} Vulnerability"
    return "Security Vulnerability"


def _excluded_hashes() -> set[str]:
    """벤치 4종 + OWASP 홀드아웃 + v13/v14 학습셋 → 전부 학습 제외."""
    ex = set()
    # 학습셋(prompt 안 코드펜스)
    for name in ("lora_train_v13.jsonl", "lora_train_v13_val.jsonl",
                 "lora_train_v14.jsonl", "lora_train_v14_val.jsonl"):
        p = ROOT / "data" / name
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            if not line.strip():
                continue
            m = re.search(r"```[a-zA-Z+#./]*\n(.*?)```", json.loads(line)["prompt"], re.S)
            if m:
                ex.add(_h(m.group(1)))
    # 벤치마크(code 필드)
    for name in ("cvefixes_benchmark.jsonl", "cybernative_benchmark.jsonl",
                 "diversevul_benchmark.jsonl", "owasp_method_bench.jsonl",
                 "owasp_holdout_bench.jsonl"):
        p = ROOT / "data" / name
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                code = r.get("code") or r.get("snippet") or ""
                if code:
                    ex.add(_h(code))
    # OWASP 홀드아웃 자바 원본
    try:
        from scripts.owasp_benchmark_cases import build_cases, JAVA_DIR, _extract_code
        for c in build_cases():
            jf = JAVA_DIR / f"{c['id']}.java"
            if jf.exists():
                ex.add(_h(_extract_code(jf)))
    except Exception as e:  # noqa: BLE001
        print(f"  (OWASP 해시 스킵: {e})")
    return ex


def _vuln_comp(name: str) -> str:
    name = (name or "Security Vulnerability").strip().split(".")[0]
    if len(name) > 70:  # 단어 경계에서 자름(문장 중간 절단 방지)
        name = name[:70].rsplit(" ", 1)[0]
    low = name.lower()
    sev, cvss = ("CRITICAL", "9.8") if any(
        k in low for k in ("inject", "rce", "command", "deserial", "eval", "overflow",
                           "out-of-bounds write", "use after free", "double free", "type confusion")
    ) else ("HIGH", "8.1")
    return f"VULNERABILITY: {name}\nSEVERITY: {sev}\nCVSS: {cvss}"


# ── stage 1: 후보 수집 ─────────────────────────────────────────────────────────

def collect_candidates(primevul_n: int, cyber_vuln_n: int, out: Path):
    from datasets import load_dataset
    rng = random.Random(SEED)
    excl = _excluded_hashes()
    seen: set[str] = set()
    rows: list[dict] = []
    print(f"제외 해시 {len(excl)}개 (벤치4종+OWASP홀드아웃+v13/v14 학습셋)")

    def add(code, label, lang, name, src):
        hh = _h(code)
        if hh in excl or hh in seen:
            return False
        seen.add(hh)
        rows.append({"language": lang, "code": code, "label": label,
                     "vuln_name": name, "src": src, "hash": hh})
        return True

    # 1) PrimeVul 취약 — train_paired의 취약 쪽 (짝 안전은 같은 commit이라 버림: V14 교훈)
    k = primevul_n // 2
    got = 0
    vuln_commits: set[str] = set()
    ds = load_dataset("ASSERT-KTH/PrimeVul", split="train_paired", streaming=True)
    for r in ds:
        if got >= k:
            break
        if not r.get("is_vulnerable"):
            continue
        code = (r.get("func") or "").strip()
        if not (MIN_LEN <= len(code) <= MAX_LEN) or _is_owasp(code):
            continue
        name = _cwe_name(r.get("cwe"))
        if add(code, "vuln", _cpp_or_c(code), name, "primevul_paired_vuln"):
            vuln_commits.add(str(r.get("commit_id") or ""))
            got += 1
    print(f"PrimeVul 취약(paired 취약쪽): {got}")

    # 2a) PrimeVul 안전 절반 — train_paired의 **안전쪽**, 단 취약에 쓴 commit 제외
    #     (v16.0 교훈: 안전을 unpaired에서만 뽑으면 "paired 스타일=취약" 지름길 학습)
    got = 0
    ds = load_dataset("ASSERT-KTH/PrimeVul", split="train_paired", streaming=True)
    for r in ds:
        if got >= k // 2:
            break
        if r.get("is_vulnerable") or str(r.get("commit_id") or "") in vuln_commits:
            continue
        code = (r.get("func") or "").strip()
        if not (MIN_LEN <= len(code) <= MAX_LEN) or _is_owasp(code):
            continue
        if add(code, "safe", _cpp_or_c(code), None, "primevul_paired_safe"):
            got += 1
    print(f"PrimeVul 안전(paired 안전쪽, commit-disjoint): {got}")

    # 2b) PrimeVul 안전 나머지 — train_unpaired
    got = 0
    ds = load_dataset("ASSERT-KTH/PrimeVul", split="train_unpaired", streaming=True)
    scanned = 0
    n_safe = sum(1 for r in rows if r["label"] == "safe")
    need = k - n_safe
    for r in ds:
        scanned += 1
        if got >= need or scanned > 120_000:
            break
        if r.get("is_vulnerable"):
            continue
        code = (r.get("func") or "").strip()
        if not (MIN_LEN <= len(code) <= MAX_LEN) or _is_owasp(code):
            continue
        if add(code, "safe", _cpp_or_c(code), None, "primevul_unpaired_safe"):
            got += 1
    print(f"PrimeVul 안전(unpaired): {got} (스캔 {scanned})")

    # 3) CyberNative — 행 번갈아 취약/안전 (같은 행의 두 면은 절대 같이 안 씀).
    #    v16.0 교훈: 취약쪽만 넣으면 "CyberNative 스타일=취약" 지름길 → FPR 92%.
    got_v = got_s = 0
    ds = load_dataset("CyberNative/Code_Vulnerability_Security_DPO",
                      split="train", streaming=True)
    scanned = 0
    for r in ds:
        scanned += 1
        if (got_v >= cyber_vuln_n and got_s >= cyber_vuln_n) or scanned > 30_000:
            break
        lang = CYBER_LANG.get(str(r.get("lang", "")).strip().lower())
        if not lang:
            continue
        take_vuln = scanned % 2 == 0
        if take_vuln and got_v >= cyber_vuln_n:
            take_vuln = False
        if not take_vuln and got_s >= cyber_vuln_n:
            take_vuln = True
            if got_v >= cyber_vuln_n:
                continue
        if take_vuln:
            code = _extract_md(r.get("rejected"))
            if not (40 <= len(code) <= 1600) or _is_owasp(code):
                continue
            name = (r.get("vulnerability") or "").strip()
            if add(code, "vuln", lang, name, "cyber_vuln"):
                got_v += 1
        else:
            code = _extract_md(r.get("chosen"))
            if not (40 <= len(code) <= 1600) or _is_owasp(code):
                continue
            if add(code, "safe", lang, None, "cyber_safe"):
                got_s += 1
    print(f"CyberNative 취약 {got_v} / 안전 {got_s} (행 disjoint)")

    rng.shuffle(rows)
    out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                   encoding="utf-8")
    nv = sum(1 for r in rows if r["label"] == "vuln")
    print("─" * 60)
    print(f"후보 {len(rows)} (취약 {nv} / 안전 {len(rows) - nv}) → {out}")
    print("다음: (선택) python scripts/distill_v15_labels.py  →  "
          "python -m ml.build_dataset_v16 --stage build")


# ── stage 2: 최종 학습셋 빌드 ──────────────────────────────────────────────────

def build_final(out: Path):
    rng = random.Random(SEED)

    def load(p):
        return [json.loads(l) for l in open(p) if l.strip()]

    if not CANDIDATES.exists():
        sys.exit(f"후보 파일 없음: {CANDIDATES} — 먼저 --stage candidates 실행")

    # 증류 votes 로드(있으면). hash → votes
    distill: dict[str, dict] = {}
    if DISTILL.exists():
        for r in load(DISTILL):
            distill[r["hash"]] = r.get("votes", {})
        print(f"증류 라벨 {len(distill)}개 로드")
    else:
        print("증류 파일 없음 — 원 라벨 그대로 사용 (scripts/distill_v15_labels.py 로 생성 가능)")

    cands = load(CANDIDATES)
    kept, dropped = [], 0
    for r in cands:
        v = distill.get(r["hash"])
        # 증류 규칙: GT=안전인데 v14(고정밀)가 취약이라 하면 라벨 노이즈 의심 → 제외.
        # GT=취약은 교사 판정과 무관하게 유지(재현율 우선).
        if v and r["label"] == "safe" and v.get("v14"):
            dropped += 1
            continue
        kept.append(r)
    if distill:
        print(f"증류 필터: 안전후보 {dropped}개 제외 (v14 교사가 취약 판정)")

    add_rows = []
    for r in kept:
        comp = _vuln_comp(r.get("vuln_name")) if r["label"] == "vuln" else NONE_COMPLETION
        add_rows.append({"prompt": build_ft_user_prompt(r["language"], r["code"]),
                         "completion": comp, "src": r["src"]})

    # V13(실제 CVE 백본) 전량 + 신규
    v13 = [{**r, "src": "v13"} for r in
           load(ROOT / "data" / "lora_train_v13.jsonl") +
           load(ROOT / "data" / "lora_train_v13_val.jsonl")]
    allrows = v13 + add_rows
    rng.shuffle(allrows)
    kv = max(1, int(len(allrows) * 0.10))
    val, train = allrows[:kv], allrows[kv:]

    def strip(r):
        return {"prompt": r["prompt"], "completion": r["completion"]}

    out.write_text("\n".join(json.dumps(strip(r), ensure_ascii=False) for r in train) + "\n",
                   encoding="utf-8")
    vp = out.with_name(out.stem + "_val.jsonl")
    vp.write_text("\n".join(json.dumps(strip(r), ensure_ascii=False) for r in val) + "\n",
                  encoding="utf-8")

    nv = sum(1 for r in allrows if "NONE" not in r["completion"])
    print("─" * 60)
    print(f"V13 {len(v13)} + 신규 {len(add_rows)} = 총 {len(allrows)} "
          f"(취약 {nv} / 안전 {len(allrows) - nv})")
    print("출처:", dict(Counter(r["src"] for r in allrows)))
    print(f"train {len(train)} | val {len(val)}")
    print(f"저장: {out}\n검증: {vp}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=["candidates", "build"], required=True)
    ap.add_argument("--primevul", type=int, default=3000, help="PrimeVul 총량(취약/안전 반반)")
    ap.add_argument("--cyber-vuln", type=int, default=600, help="CyberNative 취약-only 추가량")
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "lora_train_v16.jsonl")
    a = ap.parse_args()
    if a.stage == "candidates":
        collect_candidates(a.primevul, a.cyber_vuln, CANDIDATES)
    else:
        build_final(a.out)
