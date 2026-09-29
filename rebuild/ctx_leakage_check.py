"""
CTX-1 — 문맥 텍스트 라벨 누출 기계 점검 (사양서 §3 "절대 넣지 말 것")
=====================================================================
사양서는 `check_repo_leakage_and_keywords.py`를 돌리라고 지시하지만, 그 스크립트는
**cvefixes 학습셋의 repo 단위 분할 누수**를 보는 도구라 문맥 텍스트에는 적용되지 않는다.
(입력이 HuggingFace 데이터셋 스트림이고, 문자열 검사 기능이 없다.)
그래서 같은 목적("문맥에 라벨이 새지 않았는가")을 문맥 텍스트에 대해 수행하는 검사를 따로 둔다.
이 대체 사실은 CTX_RESULTS.md §미실행 항목에 명시한다.

점검 항목
  A. 우리가 **파일 본문 외의 것을 넣지 않았음**을 증명 — 문맥의 모든 코드 줄이
     캐시된 원본 파일 안에 실제로 존재하는가 (구분선 주석 제외).
  B. 금지 문자열 — CVE-####-####, CWE-###(응답 포맷 꼬리 제외), "commit", 날짜, 브랜치명
  C. 라벨 비대칭 — 취약본 쪽 문맥과 패치본 쪽 문맥에서 보안 키워드 출현률이 다른가
     (다르면 문맥 자체가 라벨의 대리 신호가 된다)

실행: python rebuild/ctx_leakage_check.py
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
CACHE = DATA / "ctx_cache"
OUT = ROOT / "out"

TAIL_MARK = "Respond in exactly this format:"
CTX_RE = re.compile(r"Surrounding file context \(same file, for reference\):\n\n```\w*\n(.*?)\n```", re.S)

CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
CWE_RE = re.compile(r"CWE-\d{1,4}", re.I)
DATE_RE = re.compile(r"\b(19|20)\d{2}-\d{2}-\d{2}\b")
SEC_KW = ["vulnerab", "exploit", "security", "overflow", "sanitiz", "out-of-bounds",
          "use-after-free", "double free", "buffer over", "attacker", "malicious",
          "fix", "patch", "bug", "crash", "oob", "heap", "underflow"]
SEPARATORS = {"/* ---- */", ""}


def sections_lines(ctx: str) -> list[str]:
    out = []
    for ln in ctx.splitlines():
        s = ln.strip()
        if s.startswith("// ---- ") and s.endswith(" ----"):
            continue
        if s in SEPARATORS:
            continue
        out.append(ln)
    return out


def main() -> None:
    detail = {(d["pair_id"], d["label"]): d for d in
              (json.loads(l) for l in (OUT / "ctx_collect_detail.jsonl").open())}
    t1 = [json.loads(l) for l in (DATA / "ctx_T1.jsonl").open()]

    report: dict = {"n": len(t1)}

    # ── A. 문맥 = 원본 파일의 부분집합인가 ────────────────────────────────────
    bad_lines, checked_lines, files_missing = 0, 0, 0
    for r in t1:
        d = detail[(r["meta"]["pair_id"], r["meta"]["label"])]
        key = f"blob_{d['repo'].replace('/', '__')}_{d['sha']}_{d['path'].replace('/', '__')}"
        p = CACHE / key
        if not p.exists():
            files_missing += 1
            continue
        src = p.read_bytes().decode("utf-8", errors="replace")
        # 블록을 문자 오프셋으로 자르므로 첫 줄/끝 줄이 원본 줄의 **일부**일 수 있다
        # (예: `} Foo;  /* 주석 */` 중 `} Foo;`까지만). 점검의 관심사는
        # "원본에 없던 내용을 만들어 넣었는가"이므로 원문 부분문자열 여부로 본다.
        srcset = set(l.strip() for l in src.splitlines())
        m = CTX_RE.search(r["prompt"])
        if not m:
            continue
        for ln in sections_lines(m.group(1)):
            checked_lines += 1
            s = ln.strip()
            if s not in srcset and s not in src:
                bad_lines += 1
    report["A_subset_of_source"] = {
        "checked_lines": checked_lines, "lines_not_in_source": bad_lines,
        "files_missing": files_missing,
        "verdict": "PASS" if bad_lines == 0 and files_missing == 0 else "FAIL",
    }

    # ── B. 금지 문자열 (응답 포맷 꼬리는 제외) ────────────────────────────────
    # 같은 쌍의 반대쪽에도 똑같이 들어 있는 문자열은 라벨을 가르지 못한다(대칭 = 무해).
    # 한쪽에만 있는 것만이 진짜 누출 후보다.
    body_of = {(r["meta"]["pair_id"], r["meta"]["label"]): r["prompt"].split(TAIL_MARK)[0] for r in t1}
    hits, asym_hits = Counter(), []
    examples: list[str] = []
    for (pid, lab), body in body_of.items():
        other = body_of.get((pid, "safe" if lab == "vuln" else "vuln"), "")
        for name, rx in (("cve_id", CVE_RE), ("cwe_id", CWE_RE), ("date", DATE_RE)):
            for m in rx.finditer(body):
                hits[name] += 1
                if m.group(0) not in other:
                    asym_hits.append(f"{pid}/{lab} {name}={m.group(0)}")
                elif len(examples) < 6:
                    examples.append(f"{pid}/{lab} {name}={m.group(0)} (쌍 양쪽 동일 — 무해)")
    report["B_forbidden_strings"] = {
        "counts": dict(hits), "asymmetric_hits": asym_hits[:20], "n_asymmetric": len(asym_hits),
        "symmetric_examples": examples,
        "verdict": "PASS" if not asym_hits else "FAIL",
    }

    # ── C. 라벨 비대칭 (문맥에만 적용 — 함수 본문은 원래 다르므로 제외) ───────
    kw = {"vuln": Counter(), "safe": Counter()}
    n_lab = Counter()
    ctx_tokens = {"vuln": 0, "safe": 0}
    for r in t1:
        lab = r["meta"]["label"]
        n_lab[lab] += 1
        m = CTX_RE.search(r["prompt"])
        ctx = (m.group(1) if m else "").lower()
        ctx_tokens[lab] += len(ctx)
        for k in SEC_KW:
            if k in ctx:
                kw[lab][k] += 1
    asym = {}
    for k in SEC_KW:
        v = kw["vuln"][k] / max(1, n_lab["vuln"])
        s = kw["safe"][k] / max(1, n_lab["safe"])
        asym[k] = {"vuln_rate": round(v, 4), "safe_rate": round(s, 4), "diff": round(v - s, 4)}
    worst = max(asym.items(), key=lambda kv: abs(kv[1]["diff"]))
    report["C_label_asymmetry"] = {
        "n_vuln": n_lab["vuln"], "n_safe": n_lab["safe"],
        "ctx_chars_vuln": ctx_tokens["vuln"], "ctx_chars_safe": ctx_tokens["safe"],
        "per_keyword": asym,
        "max_abs_diff": {"keyword": worst[0], **worst[1]},
        # 문맥 길이와 키워드 출현률이 거의 같으면, 문맥은 라벨의 대리 신호가 아니다.
        "verdict": "PASS" if abs(worst[1]["diff"]) < 0.05 else "REVIEW",
    }

    (OUT / "ctx_leakage_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(json.dumps(report, indent=2, ensure_ascii=False)[:4000])


if __name__ == "__main__":
    main()
