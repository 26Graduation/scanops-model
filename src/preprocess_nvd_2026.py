"""
NVD CVE 2026 전처리 스크립트
- Rejected / Deferred 상태 제외
- 핵심 10개 필드 추출
"""

from __future__ import annotations

import json
import os
from collections import Counter

INPUT_FILE  = "../data/nvdcve-2.0-2026.json"
OUTPUT_FILE = "../data/nvd_2026_preprocessed.json"

EXCLUDE_STATUS = {'Rejected', 'Deferred'}


# ── 헬퍼 함수 ──────────────────────────────────────────────

def get_primary_cvss(metrics: dict) -> dict | None:
    """CVSS: v3.1 Primary → v3.1 Secondary → v3.0 순으로 선택"""
    for key in ['cvssMetricV31', 'cvssMetricV30']:
        entries = metrics.get(key, [])
        for e in entries:
            if e.get('type') == 'Primary':
                return e['cvssData']
        if entries:
            return entries[0]['cvssData']
    return None


def get_cwe(weaknesses: list) -> str | None:
    """Primary CWE 우선, NVD-CWE-noinfo 등 비표준값 제외"""
    candidates = []
    for w in weaknesses:
        for d in w.get('description', []):
            if d['lang'] == 'en' and not d['value'].startswith('NVD-CWE'):
                candidates.append((w.get('type', ''), d['value']))
    for t, v in candidates:
        if t == 'Primary':
            return v
    return candidates[0][1] if candidates else None


def get_affected_products(configurations: list) -> list[str]:
    """CPE에서 vendor:product 형식으로 추출 (최대 5개)"""
    products = set()
    for config in configurations:
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                if match.get('vulnerable'):
                    parts = match['criteria'].split(':')
                    # cpe:2.3:<type>:<vendor>:<product>:...
                    if len(parts) >= 5:
                        vendor  = parts[3] if parts[3] != '*' else None
                        product = parts[4] if parts[4] != '*' else None
                        if vendor and product:
                            products.add(f"{vendor}:{product}")
    return sorted(products)[:5]


def extract_fields(item: dict) -> dict:
    """CVE 항목에서 핵심 10개 필드 추출"""
    cve     = item['cve']
    metrics = cve.get('metrics', {})
    cvss    = get_primary_cvss(metrics)

    en_desc = next(
        (d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'),
        None
    )

    return {
        "cve_id":            cve['id'],                                      # ① CVE 식별자
        "published":         cve['published'][:10],                          # ② 게시일 (YYYY-MM-DD)
        "vuln_status":       cve['vulnStatus'],                              # ③ 분석 상태
        "base_score":        cvss['baseScore']          if cvss else None,   # ④ CVSS 기본 점수
        "severity":          cvss['baseSeverity']       if cvss else None,   # ⑤ 심각도 등급
        "attack_vector":     cvss.get('attackVector')   if cvss else None,   # ⑥ 공격 벡터
        "cwe_id":            get_cwe(cve.get('weaknesses', [])),             # ⑦ 취약점 유형 (CWE)
        "affected_products": get_affected_products(cve.get('configurations', [])),  # ⑧ 영향 제품
        "cvss_vector":       cvss['vectorString']       if cvss else None,   # ⑨ CVSS 벡터 문자열
        "description":       en_desc,                                        # ⑩ 취약점 설명
    }


# ── 메인 처리 ──────────────────────────────────────────────

def main():
    print(f"[1/4] 파일 로드: {INPUT_FILE}")
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    items = data['vulnerabilities']
    print(f"      원본 CVE 수: {len(items):,}개")

    # ── 필터링 ──
    print(f"\n[2/4] 필터링 ({', '.join(EXCLUDE_STATUS)} 제외)")
    valid = [i for i in items if i['cve']['vulnStatus'] not in EXCLUDE_STATUS]

    excluded = Counter(
        i['cve']['vulnStatus'] for i in items
        if i['cve']['vulnStatus'] in EXCLUDE_STATUS
    )
    for status, cnt in excluded.items():
        print(f"      제외: {status:12} {cnt:,}개")
    print(f"      유효 데이터: {len(valid):,}개")

    # ── 필드 추출 ──
    print(f"\n[3/4] 핵심 10개 필드 추출")
    result = [extract_fields(i) for i in valid]
    print(f"      완료: {len(result):,}개")

    # ── 저장 ──
    print(f"\n[4/4] 저장: {OUTPUT_FILE}")
    output = {
        "meta": {
            "source":          "NVD CVE 2026",
            "original_count":  len(items),
            "excluded_status": list(EXCLUDE_STATUS),
            "filtered_count":  len(result),
            "fields":          list(result[0].keys()),
        },
        "data": result,
    }
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    size_mb = os.path.getsize(OUTPUT_FILE) / 1024 / 1024
    print(f"      파일 크기: {size_mb:.1f} MB")

    # ── 요약 통계 ──
    print("\n==============================")
    print("  처리 결과 요약")
    print("==============================")
    print(f"  원본       {len(items):>7,}개")
    print(f"  제외       {len(items)-len(result):>7,}개")
    print(f"  최종       {len(result):>7,}개")

    sev_cnt = Counter(r['severity'] for r in result)
    print("\n  심각도 분포:")
    for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', None]:
        c = sev_cnt.get(s, 0)
        label = s if s else '없음(분석대기)'
        bar = '█' * (c // 200)
        print(f"    {label:15} {c:5,}개  {bar}")


if __name__ == "__main__":
    main()
