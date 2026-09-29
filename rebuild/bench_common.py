"""
ScanOps 재구축 — 외부 벤치마크 공용 로직 (파서·채점)
=====================================================
eval_external.py(우리 모델, GPU)와 compare_claude_external.py(Claude, 로컬)가
"완전히 같은 파서·채점"을 쓰도록 한 파일로 모아둔다.
(eval_test.py / compare_apis.py 때는 복사로 갔지만, 이번엔 쌍 단위 채점까지
 들어가서 복사본이 3개가 되면 버그 나기 딱 좋아서 공용 모듈로 분리.)

포함:
  - parse():          4줄 출력 → (label, cwe, severity)  — eval_test.py와 동일 로직
  - score():          이진 채점 (재현율/오탐률/정밀도/F1)  — 외부 벤치마크는 CWE/SEV 채점 제외
                       (CleanVul은 CWE 라벨이 아예 없고, PrimeVul은 라벨 체계가 달라
                        불공정 채점이 되므로. 결정 근거는 노션 6단계 참고)
  - pairwise_score(): PrimeVul 논문 공식 쌍 단위 지표 (P-C / P-V / P-B / P-R)
  - load_jsonl():     jsonl 로더
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.open()]


# ── 파싱: 4줄 출력 → (label, cwe, severity) — eval_test.py와 동일 ─────────────
def parse(text: str) -> dict:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)  # 남은 추론 블록 제거
    vuln_line = sev_line = ""
    for line in text.splitlines():
        s = line.strip()
        if s.upper().startswith("VULNERABILITY:") and not vuln_line:
            vuln_line = s.split(":", 1)[1].strip()
        elif s.upper().startswith("SEVERITY:") and not sev_line:
            sev_line = s.split(":", 1)[1].strip().upper()
    if not vuln_line:
        return {"label": "parse_fail", "cwe": "", "severity": ""}
    if vuln_line.upper().startswith("NONE"):
        return {"label": "safe", "cwe": "", "severity": "NONE"}
    m = re.search(r"CWE-\d+", vuln_line)
    return {"label": "vuln", "cwe": m.group(0) if m else "", "severity": sev_line}


# ── 이진 채점: 취약/안전만 (외부 벤치마크 공통 지표) ──────────────────────────
def score(items: list[dict]) -> dict:
    vuln_gold = [p for p in items if p["meta"]["label"] == "vuln"]
    safe_gold = [p for p in items if p["meta"]["label"] == "safe"]
    tp = sum(1 for p in vuln_gold if p["label"] == "vuln")
    fp = sum(1 for p in safe_gold if p["label"] == "vuln")
    recall = tp / len(vuln_gold) if vuln_gold else 0.0
    fpr = fp / len(safe_gold) if safe_gold else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "n": len(items), "n_vuln": len(vuln_gold), "n_safe": len(safe_gold),
        "recall": round(recall, 4), "fpr": round(fpr, 4),
        "precision": round(precision, 4), "f1": round(f1, 4),
        "parse_fail": sum(1 for p in items if p["label"] == "parse_fail"),
    }


# ── 쌍 단위 채점: PrimeVul 논문("How Far Are We?") 공식 프로토콜 ─────────────
# 한 쌍 = 같은 커밋의 (취약본, 패치본). 두 판정을 조합해 4분류:
#   P-C (Pair-Correct):    취약→취약, 안전→안전  둘 다 정답  ← 이게 진짜 실력
#   P-V (Pair-Vulnerable): 둘 다 "취약"이라 답함  ← 과잉 경보형 (오탐 많은 모델)
#   P-B (Pair-Benign):     둘 다 "안전"이라 답함  ← 과소 탐지형
#   P-R (Pair-Reversed):   정반대로 답함 (취약→안전, 안전→취약)
# parse_fail이 낀 쌍은 4분류가 불가능하므로 pair_parse_fail로 따로 세고,
# 분모(n_pairs)에는 포함한다(빼면 유리하게 왜곡되므로).
def pairwise_score(items: list[dict]) -> dict:
    pairs: dict[str, dict[str, str]] = defaultdict(dict)  # pair_id → {gold_label: pred_label}
    for p in items:
        pairs[p["meta"]["pair_id"]][p["meta"]["label"]] = p["label"]

    n = pc = pv = pb = pr = bad = 0
    for pid, d in pairs.items():
        if set(d.keys()) != {"vuln", "safe"}:   # 쌍이 깨져 있으면(빌드 버그) 세지 않음
            continue
        n += 1
        v, s = d["vuln"], d["safe"]             # v=취약본에 대한 판정, s=패치본에 대한 판정
        if "parse_fail" in (v, s):
            bad += 1
        elif v == "vuln" and s == "safe":
            pc += 1
        elif v == "vuln" and s == "vuln":
            pv += 1
        elif v == "safe" and s == "safe":
            pb += 1
        else:                                    # v == "safe" and s == "vuln"
            pr += 1
    return {
        "n_pairs": n,
        "pair_correct":   {"n": pc, "rate": round(pc / n, 4) if n else 0.0},
        "pair_vulnerable": {"n": pv, "rate": round(pv / n, 4) if n else 0.0},
        "pair_benign":    {"n": pb, "rate": round(pb / n, 4) if n else 0.0},
        "pair_reversed":  {"n": pr, "rate": round(pr / n, 4) if n else 0.0},
        "pair_parse_fail": bad,
    }


# ── 리포트 조립: overall + 언어별 + (pair_id 있으면) 쌍 단위 ──────────────────
def build_report(preds: list[dict], engine: str, dataset: str) -> dict:
    report = {"engine": engine, "dataset": dataset, "overall": score(preds), "by_language": {}}
    by_lang: dict[str, list[dict]] = defaultdict(list)
    for p in preds:
        by_lang[p["meta"]["lang_group"]].append(p)
    for lang, items in sorted(by_lang.items()):
        report["by_language"][lang] = score(items)
    if preds and "pair_id" in preds[0]["meta"]:
        report["pairwise"] = pairwise_score(preds)
    return report
