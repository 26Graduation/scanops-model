"""
ScanOps 재구축 — 내부 test 오탐(FP) 감사 (로컬 실행, GPU 불필요)
=================================================================
왜 하나: 내부 test의 "안전" 라벨 = CVEfixes fixed_code("그 CVE만 패치한 코드").
여기에 다른 진짜 취약점이 남아 있을 수 있어서, Claude 오탐률 79.5%(513/645)의
일부는 정당한 지적일 가능성이 있다. "오탐 중 몇 %가 정당한 지적인가"를 숫자로
답하기 위해 상위 모델(Opus)을 심판으로 세워 표본 감사한다.
공정성을 위해 우리 모델의 오탐(~101건)에도 같은 감사를 건다.

방법:
  ① 내부 test 예측 파일에서 FP(정답 safe인데 vuln 판정) 추출
       Claude: out/compare_claude_predictions.jsonl → 언어별 층화 100건 샘플(SEED 42)
       우리:   out/test_predictions.jsonl          → 전수(~101건)
     (예측 파일에는 코드가 없어서 data/test.jsonl과 "행 순서"로 재결합 — 두 파일 모두
      test.jsonl 순서대로 기록됐음. 안전장치로 cve_id 일치 검증)
  ② 심판(claude-opus-4-8)에게 [코드 + 이미 패치된 CVE/CWE 정보 + 분석기의 주장]을
     주고 판정: VALID(주장한 취약점이 실제로 존재, 패치된 CVE와 별개) /
     INVALID(근거 없는 과잉 경보) / UNCERTAIN. 기본값을 INVALID 쪽으로 두도록
     지시(심판이 관대하면 감사 의미가 없음).
  ③ 집계 + 수동 재확인용 판정 시트(markdown) 생성 — 사람은 시트를 보고
     "심판 판정에 동의/비동의"만 체크하면 되는 형태.

출력: out/audit_{claude,ours}_fp.jsonl, out/audit_report.json, out/audit_review_sheet.md
환경변수: ANTHROPIC_API_KEY (scanops-model/.env)
실행:  .venv/bin/python rebuild/audit_false_positives.py
비용: 심판 호출 ~200건 × (입력 ~2k tok + 출력 ~150 tok) ≈ 수 달러 수준
"""
from __future__ import annotations

import json
import os
import random
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
SEED = 42
N_CLAUDE_SAMPLE = 100          # Claude FP 표본 크기 (비율 오차 ±8~9%p 수준)
JUDGE_MODEL = "claude-opus-4-8"  # 심판은 비교 대상(sonnet-5)보다 상위 모델로

# .env 로드 (compare_apis.py와 동일)
for line in (ROOT.parent / ".env").read_text().splitlines():
    if "=" in line and not line.strip().startswith("#"):
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())

CODE_FENCE = re.compile(r"```[^\n]*\n(.*?)\n```", re.S)

JUDGE_PROMPT = """You are auditing a vulnerability scanner's report for FALSE POSITIVES.

Context: The code below is the PATCHED (post-fix) version of a function that previously \
contained {cve_id} ({cwe_id}). That specific vulnerability has already been fixed. \
A scanner analyzed this patched code and still flagged it as vulnerable:

  Scanner's claim: {claimed_cwe}
  Scanner's reason: "{claimed_reason}"

```{language}
{code}
```

Question: Does the scanner's claimed vulnerability ACTUALLY exist in this code, as a real, \
exploitable issue DISTINCT from the already-patched {cve_id}?

Be skeptical. A vague or generic claim ("input is not validated", "may cause issues") without \
a concrete attack path visible in THIS code is INVALID. Only answer VALID if you can point to \
a specific flaw in the shown code that matches the claim. If the code fragment is too \
incomplete to decide, answer UNCERTAIN.

Respond in exactly this format:
VERDICT: <VALID|INVALID|UNCERTAIN>
REASON: <one-line justification pointing at specific code if VALID>"""


# ── FP 추출: 예측 파일 + test.jsonl을 행 순서로 재결합 ────────────────────────
def collect_fps(pred_path: Path, test_rows: list[dict]) -> list[dict]:
    preds = [json.loads(l) for l in pred_path.open()]
    assert len(preds) == len(test_rows), f"{pred_path.name} 행 수가 test.jsonl과 다름"
    fps = []
    for i, (p, t) in enumerate(zip(preds, test_rows)):
        assert p["meta"]["cve_id"] == t["meta"]["cve_id"], f"{i}행 meta 불일치 — 순서 깨짐"
        if p["meta"]["label"] == "safe" and p["label"] == "vuln":
            m = CODE_FENCE.search(t["prompt"])
            reason = ""
            for line in p.get("raw", "").splitlines():   # 분석기의 REASON 줄 추출
                if line.strip().upper().startswith("REASON:"):
                    reason = line.split(":", 1)[1].strip()
                    break
            fps.append({"idx": i, "meta": p["meta"], "claimed_cwe": p.get("cwe") or "(CWE unspecified)",
                        "claimed_severity": p.get("severity", ""), "claimed_reason": reason,
                        "code": m.group(1) if m else ""})
    return fps


# ── 층화 샘플링: 언어 그룹 비율을 유지하며 n건 추출 ───────────────────────────
def stratified_sample(fps: list[dict], n: int) -> list[dict]:
    if len(fps) <= n:
        return fps
    rng = random.Random(SEED)
    by_lang: dict[str, list[dict]] = defaultdict(list)
    for f in fps:
        by_lang[f["meta"]["lang_group"]].append(f)
    sampled: list[dict] = []
    for lang, items in sorted(by_lang.items()):
        k = max(1, round(n * len(items) / len(fps)))   # 비율 배분(최소 1건)
        sampled.extend(rng.sample(items, min(k, len(items))))
    rng.shuffle(sampled)
    return sampled[:n]


def parse_verdict(text: str) -> tuple[str, str]:
    verdict, reason = "PARSE_FAIL", ""
    for line in text.splitlines():
        s = line.strip()
        if s.upper().startswith("VERDICT:"):
            v = s.split(":", 1)[1].strip().upper()
            if v in {"VALID", "INVALID", "UNCERTAIN"}:
                verdict = v
        elif s.upper().startswith("REASON:"):
            reason = s.split(":", 1)[1].strip()
    return verdict, reason


def judge_all(cases: list[dict]) -> list[dict]:
    import anthropic
    client = anthropic.Anthropic()

    def run(case: dict) -> dict:
        prompt = JUDGE_PROMPT.format(
            cve_id=case["meta"]["cve_id"], cwe_id=case["meta"]["cwe_id"],
            claimed_cwe=case["claimed_cwe"], claimed_reason=case["claimed_reason"] or "(none given)",
            language=case["meta"]["language"], code=case["code"])
        try:
            r = client.messages.create(model=JUDGE_MODEL, max_tokens=1024,
                                       messages=[{"role": "user", "content": prompt}])
            raw = "".join(b.text for b in r.content if b.type == "text")
        except Exception as ex:
            raw = f"ERROR: {ex}"
        verdict, reason = parse_verdict(raw)
        return {**{k: case[k] for k in ("idx", "meta", "claimed_cwe", "claimed_reason")},
                "verdict": verdict, "judge_reason": reason}

    with ThreadPoolExecutor(max_workers=8) as ex:
        return list(ex.map(run, cases))


def summarize(results: list[dict]) -> dict:
    c = Counter(r["verdict"] for r in results)
    n = len(results)
    return {"n_audited": n,
            **{v.lower(): {"n": c.get(v, 0), "rate": round(c.get(v, 0) / n, 4) if n else 0.0}
               for v in ("VALID", "INVALID", "UNCERTAIN", "PARSE_FAIL")},
            "by_language": {lang: dict(Counter(r["verdict"] for r in results
                                               if r["meta"]["lang_group"] == lang))
                            for lang in sorted({r["meta"]["lang_group"] for r in results})}}


# ── 수동 재확인 시트: 판정별로 골고루 10건씩 뽑아 사람이 체크할 수 있게 ────────
def review_sheet(tag: str, results: list[dict], cases_by_idx: dict[int, dict], n: int = 10) -> str:
    rng = random.Random(SEED)
    pick: list[dict] = []
    for v in ("VALID", "UNCERTAIN", "INVALID"):     # VALID 우선(가장 확인 가치 높음)
        pool = [r for r in results if r["verdict"] == v]
        pick.extend(rng.sample(pool, min(len(pool), max(0, n - len(pick)))))
    lines = [f"\n## {tag} — 수동 재확인 {len(pick)}건 (심판 판정에 동의하는지 체크)\n"]
    for r in pick:
        code = cases_by_idx[r["idx"]]["code"]
        snippet = code[:1500] + ("\n… (생략)" if len(code) > 1500 else "")
        lines += [
            f"### [{r['verdict']}] test #{r['idx']} — {r['meta']['cve_id']} (패치된 CWE: {r['meta']['cwe_id']}, {r['meta']['language']})",
            f"- 분석기 주장: **{r['claimed_cwe']}** — {r['claimed_reason'] or '(사유 없음)'}",
            f"- 심판 근거: {r['judge_reason']}",
            "- [ ] 심판 판정에 동의  /  [ ] 비동의 (메모: ______)",
            f"\n```{r['meta']['language']}\n{snippet}\n```\n",
        ]
    return "\n".join(lines)


def main() -> None:
    test_rows = [json.loads(l) for l in (ROOT / "data" / "test.jsonl").open()]

    targets = {
        "claude": collect_fps(OUT / "compare_claude_predictions.jsonl", test_rows),
        "ours":   collect_fps(OUT / "test_predictions.jsonl", test_rows),
    }
    report: dict = {"judge_model": JUDGE_MODEL, "seed": SEED}
    sheet_parts = ["# 오탐 감사 — 수동 재확인 시트",
                   f"심판: {JUDGE_MODEL} / 규칙: 구체적 공격 경로가 코드에 보일 때만 VALID"]

    for tag, fps in targets.items():
        cases = stratified_sample(fps, N_CLAUDE_SAMPLE) if tag == "claude" else fps
        print(f"[{tag}] FP 전체 {len(fps)}건 중 {len(cases)}건 감사 시작")
        results = judge_all(cases)

        with (OUT / f"audit_{tag}_fp.jsonl").open("w") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        report[tag] = {"n_fp_total": len(fps), **summarize(results)}
        sheet_parts.append(review_sheet(tag, results, {c["idx"]: c for c in cases}))
        print(f"  → VALID {report[tag]['valid']['n']} / INVALID {report[tag]['invalid']['n']} "
              f"/ UNCERTAIN {report[tag]['uncertain']['n']}")

    (OUT / "audit_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
    (OUT / "audit_review_sheet.md").write_text("\n".join(sheet_parts))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"저장: {OUT}/audit_report.json, {OUT}/audit_review_sheet.md")


if __name__ == "__main__":
    main()
