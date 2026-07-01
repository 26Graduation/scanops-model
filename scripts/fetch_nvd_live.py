"""
fetch_nvd_live.py — 최신 NVD CVE 라이브 수집 (v5 벤치마크용)
============================================================
Claude/GPT 학습 컷오프 이후(최근 30~40일) 공개된 CVE를 NVD API에서 받아온다.
이 CVE들은 프런티어 LLM이 학습하지 못한 "신규 취약점"이므로,
RAG 기반 ScanOps의 강점을 검증하는 테스트 소스가 된다.

저장: data/nvdcve-2.0-live.json
"""
from __future__ import annotations
import json
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
import httpx

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / "data" / "nvdcve-2.0-live.json"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 최근 40일
end = datetime.utcnow()
start = end - timedelta(days=40)


def fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch() -> list[dict]:
    collected: list[dict] = []
    start_index = 0
    with httpx.Client(timeout=60.0) as client:
        while True:
            params = {
                "pubStartDate": fmt(start),
                "pubEndDate": fmt(end),
                "resultsPerPage": 200,
                "startIndex": start_index,
            }
            r = client.get(NVD, params=params)
            r.raise_for_status()
            body = r.json()
            vulns = body.get("vulnerabilities", [])
            collected.extend(vulns)
            total = body.get("totalResults", 0)
            start_index += len(vulns)
            print(f"  fetched {start_index}/{total}")
            if start_index >= total or not vulns:
                break
            time.sleep(6)  # NVD rate limit (no key: 5 req / 30s)
    return collected


# 무효/반려 상태 — 무조건 제외
EXCLUDE_STATUS = {"Rejected", "Rejected by CNA"}
_INVALID_DESC_RE = re.compile(r"\*\*\s*(REJECT|DISPUTED|RESERVED|UNSUPPORTED)", re.I)


def simplify(v: dict) -> dict | None:
    cve = v.get("cve", {})
    cid = cve.get("id")
    pub = cve.get("published", "")
    # ★반려(Rejected) 상태는 수집 단계에서 제외
    if cve.get("vulnStatus", "") in EXCLUDE_STATUS:
        return None
    descs = cve.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
    # placeholder(** REJECT/DISPUTED/RESERVED **) 설명문도 제외
    if _INVALID_DESC_RE.search(desc) or "DO NOT USE THIS CANDIDATE" in desc.upper():
        return None
    # CWE
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])
    # CVSS
    metrics = cve.get("metrics", {})
    score, sev = None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]["cvssData"]
            score = m.get("baseScore")
            sev = m.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            break
    if not cid or not desc:
        return None
    return {
        "cve_id": cid,
        "published": pub,
        "cwe": sorted(set(cwes)),
        "cvss": score,
        "severity": sev,
        "description": desc,
    }


def main():
    print(f"NVD 라이브 수집: {fmt(start)} ~ {fmt(end)}")
    raw = fetch()
    rows = [s for s in (simplify(v) for v in raw) if s]
    rows.sort(key=lambda r: r["published"], reverse=True)
    OUT.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n저장: {OUT}  ({len(rows)}개 CVE)")
    # 요약
    with_cwe = [r for r in rows if r["cwe"]]
    print(f"CWE 있는 CVE: {len(with_cwe)}개")
    print(f"기간: {rows[-1]['published'][:10]} ~ {rows[0]['published'][:10]}")


if __name__ == "__main__":
    main()
