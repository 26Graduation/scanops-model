"""ScanOps V15 — v13 ∨ v14 OR 앙상블 (재학습 없이 재현율+정확도 동시 향상)
================================================================
발견(3벤치 검증): v13(고재현율)과 v14(고정밀)를 **OR로 결합**하면 두 모델이 서로
놓친 취약점을 메워, 각 모델 단독보다 재현율·정확도가 모두 오르고 **3벤치 평균 전 지표에서
Grok을 능가**한다.

  판정 = (v13_LLM 취약) OR (v14_LLM 취약) OR (그래프 taint = vuln)

즉 "**하나라도 취약이라 하면 취약**". 그래프는 R2 규칙(놓친 취약만 보강)과 동일 효과라
OR에 자연히 흡수된다. 비용은 모델 2회 호출(스캐너 용도엔 허용 범위).

3벤치 평균(검증): V15 F1 70.0 / 재현율 71.5% / 오탐률 30.1% / 정확도 70.7%
                 (Grok  F1 59.9 / 재현율 64.3% / 오탐률 42.4% / 정확도 60.8%)
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


def predict(code: str, lang: str) -> dict:
    """V15 앙상블 판정.

    반환:
      {vulnerable, vulnerability, severity, cvss, source,
       votes:{v13,v14,graph}, graph:{verdict,category,reason}}
    """
    # v13·v14 두 모델 호출은 독립 → 병렬 실행(레이턴시 ~절반). 그래프는 즉시(규칙기반).
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as ex:
        f13 = ex.submit(_llm_analyze, code, lang, V13_MODEL)
        f14 = ex.submit(_llm_analyze, code, lang, V14_MODEL)
        a13, a14 = f13.result(), f14.result()
    g = analyze_code(code, lang)
    graph_vuln = g["verdict"] == "vuln"

    vulnerable = a13["vulnerable"] or a14["vulnerable"] or graph_vuln

    # 상세정보 선택: 취약이면 근거를 하나 고른다(v13 우선 → v14 → 그래프).
    if not vulnerable:
        detail = {"vulnerability": None, "severity": "NONE", "cvss": "0.0", "source": None}
    elif a13["vulnerable"]:
        detail = {"vulnerability": a13["name"], "severity": a13["severity"], "cvss": a13["cvss"], "source": "v13"}
    elif a14["vulnerable"]:
        detail = {"vulnerability": a14["name"], "severity": a14["severity"], "cvss": a14["cvss"], "source": "v14"}
    else:  # graph-only
        detail = {"vulnerability": g.get("category"), "severity": "HIGH", "cvss": "8.1", "source": "graph"}

    return {
        "vulnerable": vulnerable,
        **detail,
        "votes": {"v13": a13["vulnerable"], "v14": a14["vulnerable"], "graph": graph_vuln},
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
