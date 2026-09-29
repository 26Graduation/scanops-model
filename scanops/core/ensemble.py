"""ScanOps 앙상블 판정 (V18-lite: 구조필터 + 캘리브레이터 게이팅, 재학습 0)
================================================================
과거 V15는 **OR**('하나라도 취약이면 취약')였다: 재현율은 좋으나 약한 단일신호에도 찍혀
과탐(4벤치 FPR 37%)했다. V18-lite는 세 신호(v13·v16·graph)를 그대로 OR하지 않고
`verify_pipeline.decide()`로 게이팅한다:

  1) 구조 veto  — 완전파일인데 실행 로직 없음(선언-only·자동생성) → 무조건 SAFE(재현율 손실 0)
  2) 캘리브레이터 — 세 신호를 학습된 가중치로 결합→확률→임계값(약한 단일신호 과탐 억제)
  3) CPG 게이트  — (W4 훅) 약한 단일멤버 양성에 source→sink 요구, 없으면 drop

홀드아웃(leave-one-bench-out) 검증: 오탐률 37→~30(무Claude). 재현율은 W4 CPG로 회복 예정.
serving은 v13/v16/graph 판정만 계산하면 decide()가 최종 판정. 가중치는
scanops/core/calibrator_weights.json(무의존 로드).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from scanops.core.multi_graph import analyze as analyze_code

V13_MODEL = os.getenv("SCANOPS_V13_MODEL", "qwen2.5-coder-security-v13-7b:latest")
V14_MODEL = os.getenv("SCANOPS_V14_MODEL", "qwen2.5-coder-security-v14-7b:latest")

_NONE = ("NONE", "—", "N/A", "")


def _llm_analyze(code: str, lang: str, model: str) -> dict:
    """단일 모델 판정 → {vulnerable, name, severity, cvss}. 에러/파싱실패는 안전으로."""
    from scripts.benchmark_qwen_rag import call_model, parse_response, build_ft_user_prompt
    try:
        raw, _ = call_model(build_ft_user_prompt(lang, code), model, is_finetuned=True, timeout=60)
        p = parse_response(raw)
        name = (p.get("VULNERABILITY") or "").strip()
        vuln = bool(name) and name.upper() not in _NONE
        return {"vulnerable": vuln, "name": name if vuln else None,
                "severity": p.get("SEVERITY"), "cvss": p.get("CVSS")}
    except Exception as e:  # noqa: BLE001
        return {"vulnerable": False, "name": None, "severity": None, "cvss": None, "error": str(e)}


def predict(code: str, lang: str, *, assume_complete_file: bool = True,
            cpg_gate=None) -> dict:
    """V18-lite 앙상블 판정 (구조필터 + 캘리브레이터 게이팅, 재학습 0).

    OR('하나라도 취약') 대신 verify_pipeline.decide()로 최종 판정한다:
      1) 구조 veto(선언-only·생성파일 SAFE)  2) 캘리브레이터(세 신호 학습결합)
      3) CPG 게이트(cpg_gate 넘기면, W4).
    두 번째 멤버(V14_MODEL 슬롯)는 캘리브레이터의 'v16' 신호로 취급(운영 배포=v13∨v16).

    assume_complete_file: 프로덕션 완전파일=True(구조 veto 신뢰), 벤치 조각=False.
    반환: {vulnerable, vulnerability, severity, cvss, source, prob, decision_reason,
           votes:{v13,v16,graph}, graph:{...}}
    """
    from concurrent.futures import ThreadPoolExecutor
    from scanops.core.verify_pipeline import decide
    with ThreadPoolExecutor(max_workers=2) as ex:
        f13 = ex.submit(_llm_analyze, code, lang, V13_MODEL)
        f14 = ex.submit(_llm_analyze, code, lang, V14_MODEL)
        a13, a14 = f13.result(), f14.result()
    g = analyze_code(code, lang)
    graph_vuln = g["verdict"] == "vuln"

    signals = {"v13": a13["vulnerable"], "v16": a14["vulnerable"], "graph": graph_vuln}
    dec = decide(signals, code, lang,
                 assume_complete_file=assume_complete_file, cpg_gate=cpg_gate)
    vulnerable = dec.vulnerable

    # 상세정보 선택: 취약이면 근거를 하나 고른다(v13 우선 → v16 → 그래프).
    if not vulnerable:
        detail = {"vulnerability": None, "severity": "NONE", "cvss": "0.0", "source": None}
    elif a13["vulnerable"]:
        detail = {"vulnerability": a13["name"], "severity": a13["severity"], "cvss": a13["cvss"], "source": "v13"}
    elif a14["vulnerable"]:
        detail = {"vulnerability": a14["name"], "severity": a14["severity"], "cvss": a14["cvss"], "source": "v16"}
    else:  # graph-only
        detail = {"vulnerability": g.get("category"), "severity": "HIGH", "cvss": "8.1", "source": "graph"}

    return {
        "vulnerable": vulnerable,
        **detail,
        "prob": round(dec.prob, 4),
        "decision_reason": dec.reason,
        "votes": signals,
        "graph": {"verdict": g["verdict"], "category": g.get("category"), "reason": g.get("reason")},
    }


def predict_single(code: str, lang: str, model: str = V13_MODEL) -> dict:
    """단일 모델 + 코드그래프 (R2 결합). V13 배포용.

    판정 = (모델 LLM 취약) OR (그래프 taint = vuln)   # 그래프가 놓친 취약 보강
    """
    a = _llm_analyze(code, lang, model)
    g = analyze_code(code, lang)
    graph_vuln = g["verdict"] == "vuln"
    vulnerable = a["vulnerable"] or graph_vuln
    if not vulnerable:
        detail = {"vulnerability": None, "severity": "NONE", "cvss": "0.0", "source": None}
    elif a["vulnerable"]:
        detail = {"vulnerability": a["name"], "severity": a["severity"], "cvss": a["cvss"], "source": "llm"}
    else:
        detail = {"vulnerability": g.get("category"), "severity": "HIGH", "cvss": "8.1", "source": "graph"}
    return {
        "vulnerable": vulnerable, **detail,
        "votes": {"llm": a["vulnerable"], "graph": graph_vuln},
        "graph": {"verdict": g["verdict"], "category": g.get("category"), "reason": g.get("reason")},
    }


if __name__ == "__main__":  # 간단 스모크
    demo = ("Python", "q='SELECT * FROM u WHERE id='+request.args.get('id')\ncur.execute(q)")
    import json
    print(json.dumps(predict(demo[1], demo[0]), ensure_ascii=False, indent=2))
