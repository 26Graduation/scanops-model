"""하이브리드 판정 집계 — LLM · Joern · 자체 graph

정책(policy)은 Phase 2 의 **사전 등록 precision 게이트 판정**을 그대로 옮긴 것이다.
근거는 JOERN_HYBRID_REPORT.md §4·§5.

공통 불변 규칙 (ABLATION_RESULTS.md §2-0 근거):
  - joern/graph 의 "safe" 는 어떤 판정도 덮지 않는다 (자체 graph safe 의 43.8%가 오판,
    Java 만 보면 42.5%).
  - 자체 graph "vuln" 은 모든 정책에서 **마지막 폴백**으로 유지한다 (precision 0.60).
  - joern 미도착(None)이면 LLM(+graph) 결과를 status=PARTIAL 로 반환한다.
  - LLM Critic 없음 — joern 결과를 LLM 에게 되물어 재판정하지 않는다 (CTX-1 KILL).

DELTA·TAU 는 **코드에 임의 숫자를 넣지 않는다.** 우선순위:
  1) 환경변수 SCANOPS_HYBRID_DELTA / SCANOPS_HYBRID_TAU
  2) rebuild/out/joern_tune_selection.json (Phase 2-① 실측 산출물)
  3) 없으면 None → JOERN-AS-SIGNAL 사용 불가(자동으로 JOERN-NO-BETTER 로 강등)
"""
from __future__ import annotations

import json
import os
from pathlib import Path

VALID_POLICIES = ("TRUST-JOERN", "JOERN-AS-SIGNAL", "JOERN-NO-BETTER", "INCONCLUSIVE")

_SELECTION = Path(__file__).resolve().parents[2] / "rebuild" / "out" / "joern_tune_selection.json"


def _load_tuned() -> tuple[float | None, float | None]:
    d = os.getenv("SCANOPS_HYBRID_DELTA")
    t = os.getenv("SCANOPS_HYBRID_TAU")
    if d is not None and t is not None:
        return float(d), float(t)
    try:
        sel = json.loads(_SELECTION.read_text())
        tau_block = sel.get("TAU_fpr35") or sel.get("TAU_f1max") or {}
        return float(sel["DELTA"]), float(tau_block["tau"])
    except Exception:  # noqa: BLE001
        return None, None


DELTA, TAU = _load_tuned()


# ── 응답 헬퍼 — 반환 필드는 세 경로 모두 동일하게 맞춘다 ─────────────────────

_FIELDS = ("detected", "source", "evidence", "status", "score",
           "vulnerability", "severity", "cvss", "reason")


def _base(status: str, score) -> dict:
    return {"detected": False, "source": "llm", "evidence": None, "status": status,
            "score": score, "vulnerability": "NONE", "severity": "NONE",
            "cvss": None, "reason": ""}


def vuln(source: str, evidence, status: str, score=None,
         vulnerability: str = "", severity: str = "", cvss=None, reason: str = "") -> dict:
    r = _base(status, score)
    r.update(detected=True, source=source, evidence=evidence,
             vulnerability=vulnerability or "DETECTED", severity=severity or "UNKNOWN",
             cvss=cvss, reason=reason)
    return r


def safe(source: str, status: str, score=None) -> dict:
    r = _base(status, score)
    r["source"] = source
    return r


def llm_result(llm: dict, source: str, status: str) -> dict:
    return {"detected": bool(llm.get("detected")), "source": source, "evidence": None,
            "status": status, "score": llm.get("score"),
            "vulnerability": llm.get("vulnerability") or "NONE",
            "severity": llm.get("severity") or "NONE",
            "cvss": llm.get("cvss"), "reason": llm.get("reason") or ""}


# ── 집계 ────────────────────────────────────────────────────────────────────

def aggregate(llm: dict, joern: dict | None, graph: dict | None, policy: str) -> dict:
    if policy not in VALID_POLICIES:
        raise ValueError(policy)

    st = "DONE" if joern is not None else "PARTIAL"
    graph_vuln = bool(graph and graph.get("verdict") == "vuln")
    joern_vuln = bool(joern and joern.get("verdict") == "vuln")
    jpath = (joern or {}).get("path") or (joern or {}).get("categories")

    if policy == "TRUST-JOERN":
        if joern_vuln:
            return vuln(source="joern", evidence=jpath, status=st, score=llm.get("score"),
                        vulnerability=(joern.get("categories") or ["DETECTED"])[0],
                        severity="UNKNOWN", reason="Joern taint flow")
        if llm.get("detected"):
            return llm_result(llm, source="llm", status=st)
        if graph_vuln:
            return vuln(source="graph", evidence=graph.get("reason"), status=st,
                        score=llm.get("score"), vulnerability=graph.get("category", "DETECTED"),
                        reason=graph.get("reason", ""))
        return safe(source="llm", status=st, score=llm.get("score"))

    if policy == "JOERN-AS-SIGNAL":
        if llm.get("score") is None or DELTA is None or TAU is None:
            # Phase 1-B 실패 또는 τ·δ 미확정 → NO-BETTER 로 강등하고 표시를 남긴다
            r = aggregate(llm, joern, graph, "JOERN-NO-BETTER")
            r["policy_fallback"] = True
            return r
        s = float(llm["score"]) + (DELTA if joern_vuln else 0.0)
        if s >= TAU:
            return vuln(source="llm+joern", evidence=jpath, status=st, score=s,
                        vulnerability=llm.get("vulnerability") or "DETECTED",
                        severity=llm.get("severity") or "UNKNOWN",
                        cvss=llm.get("cvss"), reason=llm.get("reason") or "")
        if graph_vuln:
            return vuln(source="graph", evidence=graph.get("reason"), status=st, score=s,
                        vulnerability=graph.get("category", "DETECTED"),
                        reason=graph.get("reason", ""))
        return safe(source="llm+joern", status=st, score=s)

    # JOERN-NO-BETTER / INCONCLUSIVE — Joern 을 판정에 넣지 않는다
    if llm.get("detected"):
        return llm_result(llm, source="llm", status="DONE")
    if graph_vuln:
        return vuln(source="graph", evidence=graph.get("reason"), status="DONE",
                    score=llm.get("score"), vulnerability=graph.get("category", "DETECTED"),
                    reason=graph.get("reason", ""))
    return safe(source="llm", status="DONE", score=llm.get("score"))


def policy_for(language: str, policy_map: dict | str) -> str:
    """언어별 판정이 갈린 경우를 위한 조회. 문자열이면 그대로 쓴다."""
    if isinstance(policy_map, str):
        return policy_map
    return policy_map.get(language) or policy_map.get("_default") or "JOERN-NO-BETTER"
