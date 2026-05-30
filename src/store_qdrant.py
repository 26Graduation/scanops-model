"""
FAISS 인덱스 → Qdrant 벡터 DB 마이그레이션

기존에 embed_cve.py로 생성한 임베딩 벡터와 CVE 메타데이터를
Qdrant 컬렉션에 업로드합니다.

실행 전 Qdrant 컨테이너가 동작 중이어야 합니다:
  docker run -d --name qdrant -p 6333:6333 qdrant/qdrant
"""

import json
import os
import numpy as np
import faiss
from tqdm import tqdm
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    VectorParams,
    PointStruct,
    Filter,
    FieldCondition,
    MatchValue,
    QueryRequest,
)

# ── 경로 설정 ──────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

PREPROCESSED_PATH = os.path.join(DATA_DIR, "nvd_2026_preprocessed.json")
FAISS_INDEX_PATH  = os.path.join(DATA_DIR, "cve_index.faiss")
ID_MAP_PATH       = os.path.join(DATA_DIR, "cve_id_map.json")

QDRANT_URL        = "http://localhost:6333"
COLLECTION_NAME   = "cve_vulnerabilities"
VECTOR_DIM        = 384      # bge-small-en-v1.5 출력 차원
BATCH_SIZE        = 256      # 한 번에 업로드할 포인트 수


# ── 1. 기존 데이터 로드 ────────────────────────────────────
def load_data():
    print("[1/4] 기존 데이터 로드...")

    # FAISS 인덱스에서 벡터 추출
    index = faiss.read_index(FAISS_INDEX_PATH)
    vectors = index.reconstruct_n(0, index.ntotal)   # (N, 384) numpy array
    print(f"      → FAISS 벡터 수: {len(vectors):,}  shape: {vectors.shape}")

    # CVE ID 순서 맵
    with open(ID_MAP_PATH, encoding="utf-8") as f:
        cve_ids = json.load(f)
    print(f"      → CVE ID 수: {len(cve_ids):,}")

    # 원본 메타데이터 (payload로 저장)
    with open(PREPROCESSED_PATH, encoding="utf-8") as f:
        raw = json.load(f)
    records = {r["cve_id"]: r for r in raw["data"]}
    print(f"      → 메타데이터 레코드 수: {len(records):,}")

    return vectors, cve_ids, records


# ── 2. Qdrant 컬렉션 생성 ──────────────────────────────────
def create_collection(client: QdrantClient):
    print(f"\n[2/4] 컬렉션 '{COLLECTION_NAME}' 생성...")

    existing = [c.name for c in client.get_collections().collections]
    if COLLECTION_NAME in existing:
        print(f"      → 기존 컬렉션 삭제 후 재생성")
        client.delete_collection(COLLECTION_NAME)

    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(
            size=VECTOR_DIM,
            distance=Distance.COSINE,   # cosine similarity 사용
        ),
    )
    print(f"      → 생성 완료 (dim={VECTOR_DIM}, distance=COSINE)")


# ── 3. 벡터 + 메타데이터 업로드 ───────────────────────────
def upload_points(client: QdrantClient, vectors, cve_ids, records):
    print(f"\n[3/4] Qdrant 업로드 중 (배치 크기={BATCH_SIZE})...")

    total = len(cve_ids)
    uploaded = 0

    for start in tqdm(range(0, total, BATCH_SIZE), desc="업로드"):
        end = min(start + BATCH_SIZE, total)
        batch_ids   = list(range(start, end))          # integer ID
        batch_vecs  = vectors[start:end].tolist()
        batch_cveids = cve_ids[start:end]

        points = []
        for i, (vec, cve_id) in enumerate(zip(batch_vecs, batch_cveids)):
            meta = records.get(cve_id, {})
            payload = {
                "cve_id":           cve_id,
                "published":        meta.get("published"),
                "vuln_status":      meta.get("vuln_status"),
                "base_score":       meta.get("base_score"),
                "severity":         meta.get("severity"),
                "attack_vector":    meta.get("attack_vector"),
                "cwe_id":           meta.get("cwe_id"),
                "affected_products": meta.get("affected_products", []),
                "cvss_vector":      meta.get("cvss_vector"),
                "description":      meta.get("description", ""),
            }
            points.append(PointStruct(id=start + i, vector=vec, payload=payload))

        client.upsert(collection_name=COLLECTION_NAME, points=points)
        uploaded += len(points)

    print(f"      → 총 {uploaded:,}개 포인트 업로드 완료")


# ── 4. 업로드 검증 ─────────────────────────────────────────
def verify(client: QdrantClient, vectors, cve_ids):
    print(f"\n[4/4] 업로드 검증...")

    info = client.get_collection(COLLECTION_NAME)
    count = info.points_count
    print(f"      → 컬렉션 내 포인트 수: {count:,}")
    assert count == len(cve_ids), f"불일치! 예상={len(cve_ids)}, 실제={count}"
    print(f"      → 포인트 수 일치 ✓")

    # 샘플 벡터로 검색 테스트 (v1.13+ query_points API 사용)
    sample_vec = vectors[0].tolist()
    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=sample_vec,
        limit=3,
        with_payload=True,
    ).points
    print(f"\n      [검색 테스트] 첫 번째 벡터로 유사도 검색 결과:")
    for r in results:
        print(f"        score={r.score:.4f}  {r.payload['cve_id']}  "
              f"severity={r.payload['severity']}  base_score={r.payload['base_score']}")

    # 필터 검색 테스트 (CRITICAL 심각도만)
    critical_results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=vectors[100].tolist(),
        query_filter=Filter(
            must=[FieldCondition(key="severity", match=MatchValue(value="CRITICAL"))]
        ),
        limit=3,
        with_payload=True,
    ).points
    print(f"\n      [필터 검색 테스트] severity=CRITICAL 조건:")
    for r in critical_results:
        print(f"        score={r.score:.4f}  {r.payload['cve_id']}  "
              f"base_score={r.payload['base_score']}")

    print("\n모든 검증 완료.")


# ── 메인 ───────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"Qdrant 연결: {QDRANT_URL}")
    client = QdrantClient(url=QDRANT_URL)
    print(f"서버 상태: {client.get_collections()}\n")

    vectors, cve_ids, records = load_data()
    create_collection(client)
    upload_points(client, vectors, cve_ids, records)
    verify(client, vectors, cve_ids)

    print(f"\n✓ Qdrant 컬렉션 '{COLLECTION_NAME}' 준비 완료")
    print(f"  대시보드: http://localhost:6333/dashboard")
