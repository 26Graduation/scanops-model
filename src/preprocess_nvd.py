import json
import re
from datetime import datetime, timezone
from pathlib import Path

INPUT = Path("data/nvdcve-2.0-filtered.json")
OUTPUT = Path("data/nvdcve-2.0-preprocessed.json")

TODAY = datetime(2026, 4, 30, tzinfo=timezone.utc)


def cvss_score_to_severity(score: float) -> str:
    if score == 0.0:
        return "NONE"
    elif score < 4.0:
        return "LOW"
    elif score < 7.0:
        return "MEDIUM"
    elif score < 9.0:
        return "HIGH"
    else:
        return "CRITICAL"


def parse_date(dt_str: str) -> datetime:
    # NVD 날짜 형식: "2026-04-21T13:16:20.380"
    return datetime.fromisoformat(dt_str).replace(tzinfo=timezone.utc)


def normalize_description(text: str) -> str:
    text = text.strip()
    text = re.sub(r"\s+", " ", text)
    return text


def preprocess(raw: dict) -> dict:
    # ── CVSS 통합 점수 (v4 우선) ──────────────────────────────
    v4 = raw["cvss_v4"]
    v3 = raw["cvss_v3"]

    if v4 is not None:
        score = float(v4["baseScore"])
        severity = v4["baseSeverity"]
        score_version = "v4"
        vector_string = v4["vectorString"]
    else:
        score = float(v3["baseScore"])
        severity = cvss_score_to_severity(score)
        score_version = "v3"
        vector_string = None

    # ── CWE 단일화 ────────────────────────────────────────────
    cwes = raw["cwe"]
    cwe_primary = cwes[0] if cwes else "UNKNOWN"

    # ── 날짜 파생 ─────────────────────────────────────────────
    published_dt = parse_date(raw["published"])
    modified_dt = parse_date(raw["lastModified"])
    age_days = (TODAY - published_dt).days
    days_since_modified = (TODAY - modified_dt).days

    return {
        "id": raw["id"],
        "published": raw["published"],
        "lastModified": raw["lastModified"],
        "age_days": age_days,
        "days_since_modified": days_since_modified,
        "description": normalize_description(raw["description"]),
        "score": score,
        "severity": severity,
        "score_version": score_version,
        "vector_string": vector_string,
        "cvss_v3_score": float(v3["baseScore"]),
        "cwe_primary": cwe_primary,
        "cwe": cwes,
        "reference_count": len(raw["references"]),
        "references": raw["references"],
    }


def main():
    with open(INPUT) as f:
        data = json.load(f)

    processed = [preprocess(d) for d in data]

    with open(OUTPUT, "w") as f:
        json.dump(processed, f, indent=2, ensure_ascii=False)

    # 검증 출력
    from collections import Counter
    severities = Counter(d["severity"] for d in processed)
    score_versions = Counter(d["score_version"] for d in processed)
    unknowns = sum(1 for d in processed if d["cwe_primary"] == "UNKNOWN")

    print(f"총 {len(processed)}개 저장 → {OUTPUT}")
    print(f"severity 분포: {dict(severities)}")
    print(f"score 출처: {dict(score_versions)}")
    print(f"cwe UNKNOWN: {unknowns}개")


if __name__ == "__main__":
    main()
