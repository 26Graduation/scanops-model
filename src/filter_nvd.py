import json
from pathlib import Path

INPUT = Path("data/nvdcve-2.0-recent.json")
OUTPUT = Path("data/nvdcve-2.0-filtered.json")

VALID_STATUSES = {"Analyzed", "Modified"}


def extract_description(descriptions: list) -> str:
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def extract_cvss_v4(metrics: dict) -> dict | None:
    entries = metrics.get("cvssMetricV40", [])
    if not entries:
        return None
    data = entries[0].get("cvssData", {})
    return {
        "baseScore": data.get("baseScore"),
        "baseSeverity": data.get("baseSeverity"),
        "vectorString": data.get("vectorString"),
    }


def extract_cvss_v3(metrics: dict) -> dict | None:
    entries = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30", [])
    if not entries:
        return None
    data = entries[0].get("cvssData", {})
    return {"baseScore": data.get("baseScore")}


def extract_cwe(weaknesses: list) -> list[str]:
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            val = d.get("value", "")
            if val and val != "NVD-CWE-noinfo" and val != "NVD-CWE-Other":
                cwes.append(val)
    return list(dict.fromkeys(cwes))  # deduplicate, preserve order


def extract_references(references: list) -> list[str]:
    return [r["url"] for r in references if "url" in r]


def filter_cve(raw: dict) -> dict:
    cve = raw["cve"]
    metrics = cve.get("metrics", {})
    return {
        "id": cve["id"],
        "published": cve["published"],
        "lastModified": cve["lastModified"],
        "description": extract_description(cve.get("descriptions", [])),
        "cvss_v4": extract_cvss_v4(metrics),
        "cvss_v3": extract_cvss_v3(metrics),
        "cwe": extract_cwe(cve.get("weaknesses", [])),
        "references": extract_references(cve.get("references", [])),
    }


def main():
    with open(INPUT) as f:
        data = json.load(f)

    filtered = [
        filter_cve(v)
        for v in data["vulnerabilities"]
        if v["cve"].get("vulnStatus") in VALID_STATUSES
    ]

    with open(OUTPUT, "w") as f:
        json.dump(filtered, f, indent=2, ensure_ascii=False)

    print(f"총 {len(data['vulnerabilities'])}개 중 {len(filtered)}개 저장 → {OUTPUT}")


if __name__ == "__main__":
    main()
