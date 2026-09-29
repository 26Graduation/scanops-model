"""
현재 로컬 CVE 데이터를 Railway Qdrant에 직접 업로드

사용법:
  cd scanops-model
  source .venv/bin/activate
  QDRANT_URL=https://qdrant-production-3ef0.up.railway.app \
    python src/upload_cve_to_railway.py
"""

import json
import os
import sys
from pathlib import Path

import requests
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = BASE_DIR / "data" / "nvdcve-2.0-preprocessed.json"

QDRANT_URL      = os.environ.get("QDRANT_URL", "http://localhost:6333").rstrip("/")
COLLECTION_NAME = "cve_vulnerabilities"
VECTOR_DIM      = 384       # bge-small-en-v1.5
BATCH_SIZE      = 64
BGE_MODEL       = "BAAI/bge-small-en-v1.5"
TIMEOUT         = 60


def qdrant(method: str, path: str, **kwargs):
    """Qdrant REST API 헬퍼 (requests 직접 사용)."""
    url = f"{QDRANT_URL}{path}"
    resp = getattr(requests, method)(url, timeout=TIMEOUT, **kwargs)
    resp.raise_for_status()
    return resp.json()


def build_text(record: dict) -> str:
    cve_id = record.get("id", "")
    desc   = record.get("description", "")
    cwe    = record.get("cwe_primary", record.get("cwe", ""))
    sev    = record.get("severity", "")
    return f"CVE: {cve_id}. Severity: {sev}. CWE: {cwe}. {desc}"


def main():
    print(f"[1/4] 데이터 로드: {DATA_FILE}")
    with open(DATA_FILE, encoding="utf-8") as f:
        records = json.load(f)
    if isinstance(records, dict):
        records = records.get("data", [])
    print(f"      → CVE 레코드 수: {len(records):,}")

    print(f"\n[2/4] 임베딩 모델 로드: {BGE_MODEL}")
    model = SentenceTransformer(BGE_MODEL)

    print(f"\n[3/4] Qdrant 연결 확인: {QDRANT_URL}")
    info = qdrant("get", "/collections")
    existing = [c["name"] for c in info["result"]["collections"]]
    print(f"      → 현재 컬렉션: {existing}")

    if COLLECTION_NAME in existing:
        print(f"      → 기존 컬렉션 '{COLLECTION_NAME}' 삭제")
        qdrant("delete", f"/collections/{COLLECTION_NAME}")

    qdrant("put", f"/collections/{COLLECTION_NAME}", json={
        "vectors": {"size": VECTOR_DIM, "distance": "Cosine"}
    })
    print(f"      → 컬렉션 생성 완료 (dim={VECTOR_DIM}, COSINE)")

    print(f"\n[4/4] 벡터 임베딩 + 업로드 (배치={BATCH_SIZE})")
    total_uploaded = 0

    for start in tqdm(range(0, len(records), BATCH_SIZE), desc="업로드"):
        batch = records[start : start + BATCH_SIZE]
        texts = [build_text(r) for r in batch]
        vecs  = model.encode(texts, normalize_embeddings=True).tolist()

        points = []
        for i, (vec, rec) in enumerate(zip(vecs, batch)):
            cve_id = rec.get("id", rec.get("cve_id", f"UNK-{start+i}"))
            points.append({
                "id": start + i,
                "vector": vec,
                "payload": {
                    "cve_id":      cve_id,
                    "published":   rec.get("published"),
                    "base_score":  rec.get("cvss_v3_score", rec.get("score")),
                    "severity":    rec.get("severity"),
                    "cwe_id":      rec.get("cwe_primary", rec.get("cwe", "N/A")),
                    "description": rec.get("description", "")[:300],
                }
            })

        qdrant("put", f"/collections/{COLLECTION_NAME}/points", json={"points": points})
        total_uploaded += len(points)

    # 검증
    info = qdrant("get", f"/collections/{COLLECTION_NAME}")
    count = info["result"]["points_count"]
    print(f"\n✓ 업로드 완료: {total_uploaded:,}개 → Qdrant 컬렉션 내 {count:,}개")
    print(f"  대시보드: {QDRANT_URL}/dashboard")


if __name__ == "__main__":
    main()
