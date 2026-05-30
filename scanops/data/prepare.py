"""NVD CVE 데이터 전처리 및 Qdrant 적재 스크립트.

사용법:
  python -m scanops.data.prepare --input data/nvdcve-2.0-preprocessed.json
  python -m scanops.data.prepare --input data/nvdcve-2.0-recent.json --collection cve_vulnerabilities

데이터 선택 근거:
  - feat/hyeeun: 12,251개 (Rejected/Deferred 제외) — RAG 커버리지 우위
  - feat/sehan:    792개 (강하게 필터링) — 로컬 기본값으로 활용
  기본 실행 시 792개 데이터를 사용하며, 더 큰 NVD 피드를 --input으로 전달하면
  전처리 후 자동 적재된다.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams
from tqdm import tqdm

from scanops.core.embedder import embed_documents

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION_NAME = os.getenv("QDRANT_COLLECTION", "cve_vulnerabilities")
VECTOR_DIM = 384  # bge-small-en-v1.5
BATCH_SIZE = 128

EXCLUDE_STATUS = {"Rejected", "Deferred"}
DEFAULT_INPUT = Path(__file__).resolve().parents[2] / "data" / "nvdcve-2.0-preprocessed.json"


# ── 전처리 ──────────────────────────────────────────────────────────────────────

def _get_primary_cvss(metrics: dict) -> dict | None:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        for e in entries:
            if e.get("type") == "Primary":
                return e["cvssData"]
        if entries:
            return entries[0]["cvssData"]
    return None


def _get_cwe(weaknesses: list) -> str | None:
    candidates = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d["lang"] == "en" and not d["value"].startswith("NVD-CWE"):
                candidates.append((w.get("type", ""), d["value"]))
    for t, v in candidates:
        if t == "Primary":
            return v
    return candidates[0][1] if candidates else None


def _get_products(configurations: list) -> list[str]:
    products: set[str] = set()
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    parts = match["criteria"].split(":")
                    if len(parts) >= 5:
                        vendor = parts[3] if parts[3] != "*" else None
                        product = parts[4] if parts[4] != "*" else None
                        if vendor and product:
                            products.add(f"{vendor}:{product}")
    return sorted(products)[:5]


def preprocess_nvd_raw(raw_path: Path) -> list[dict]:
    """NVD 원본 JSON 피드를 핵심 필드만 추출해 정제한다."""
    with open(raw_path, encoding="utf-8") as f:
        data = json.load(f)

    items = data if isinstance(data, list) else data.get("vulnerabilities", [])

    records = []
    for item in items:
        cve = item.get("cve", item)
        status = cve.get("vulnStatus", "")
        if status in EXCLUDE_STATUS:
            continue

        metrics = cve.get("metrics", {})
        cvss = _get_primary_cvss(metrics)
        en_desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            None,
        )

        records.append({
            "cve_id": cve.get("id", ""),
            "published": cve.get("published", "")[:10],
            "vuln_status": status,
            "base_score": cvss["baseScore"] if cvss else None,
            "severity": cvss["baseSeverity"] if cvss else None,
            "attack_vector": cvss.get("attackVector") if cvss else None,
            "cwe_id": _get_cwe(cve.get("weaknesses", [])),
            "affected_products": _get_products(cve.get("configurations", [])),
            "cvss_vector": cvss.get("vectorString") if cvss else None,
            "description": en_desc or "",
        })

    return records


def load_preprocessed(path: Path) -> list[dict]:
    """이미 전처리된 JSON을 로드한다 (리스트 또는 {data: [...]} 형식 모두 허용)."""
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if isinstance(raw, list):
        return raw
    return raw.get("data", raw.get("vulnerabilities", []))


# ── Qdrant 적재 ─────────────────────────────────────────────────────────────────

def store_in_qdrant(
    records: list[dict],
    collection: str = COLLECTION_NAME,
    qdrant_url: str = QDRANT_URL,
    recreate: bool = False,
) -> int:
    """전처리된 레코드를 임베딩해 Qdrant에 저장하고 저장된 수를 반환한다."""
    client = QdrantClient(url=qdrant_url)

    existing = {c.name for c in client.get_collections().collections}
    if collection in existing:
        if recreate:
            print(f"[prepare] 기존 컬렉션 '{collection}' 삭제 후 재생성")
            client.delete_collection(collection)
        else:
            print(f"[prepare] 기존 컬렉션 '{collection}' 사용 (재생성 건너뜀)")
            return 0

    client.create_collection(
        collection_name=collection,
        vectors_config=VectorParams(size=VECTOR_DIM, distance=Distance.COSINE),
    )
    print(f"[prepare] 컬렉션 '{collection}' 생성 완료 (dim={VECTOR_DIM})")

    uploaded = 0
    for start in tqdm(range(0, len(records), BATCH_SIZE), desc="Qdrant 적재"):
        batch = records[start : start + BATCH_SIZE]
        texts = [r.get("description") or r.get("cve_id", "") for r in batch]
        vecs = embed_documents(texts)

        points = [
            PointStruct(
                id=start + i,
                vector=vec,
                payload={k: v for k, v in rec.items() if k != "description" or True},
            )
            for i, (rec, vec) in enumerate(zip(batch, vecs))
        ]
        client.upsert(collection_name=collection, points=points)
        uploaded += len(points)

    print(f"[prepare] 총 {uploaded:,}개 적재 완료 → {qdrant_url}/dashboard")
    return uploaded


# ── CLI 진입점 ──────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="NVD CVE 데이터를 Qdrant에 적재합니다.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="NVD JSON 파일 경로")
    parser.add_argument("--collection", default=COLLECTION_NAME)
    parser.add_argument("--qdrant-url", default=QDRANT_URL)
    parser.add_argument("--recreate", action="store_true", help="컬렉션을 강제 재생성")
    parser.add_argument("--raw", action="store_true", help="원본 NVD 피드 전처리 후 적재")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"[prepare] 파일 없음: {args.input}")
        return

    if args.raw:
        print(f"[prepare] 원본 NVD 피드 전처리 중: {args.input}")
        records = preprocess_nvd_raw(args.input)
    else:
        print(f"[prepare] 전처리된 데이터 로드 중: {args.input}")
        records = load_preprocessed(args.input)

    print(f"[prepare] 레코드 수: {len(records):,}")
    store_in_qdrant(records, collection=args.collection, qdrant_url=args.qdrant_url, recreate=args.recreate)


if __name__ == "__main__":
    main()
