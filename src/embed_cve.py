"""
CVE 데이터 임베딩 파이프라인

전처리된 CVE JSON → 텍스트 직렬화 → bge-small-en-v1.5 임베딩 → FAISS 인덱스 저장
"""

import json
import os
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

# ── 경로 설정 ──────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

INPUT_PATH = os.path.join(DATA_DIR, "nvd_2026_preprocessed.json")
FAISS_INDEX_PATH = os.path.join(DATA_DIR, "cve_index.faiss")
ID_MAP_PATH = os.path.join(DATA_DIR, "cve_id_map.json")

MODEL_NAME = "BAAI/bge-small-en-v1.5"
BATCH_SIZE = 64


# ── Step 2: 텍스트 직렬화 ──────────────────────────────────
def serialize_cve(record: dict) -> str:
    """
    CVE 레코드를 임베딩용 단일 문자열로 변환.
    필드명을 포함해 모델이 각 값의 의미를 파악할 수 있도록 구성.
    """
    products = ", ".join(record.get("affected_products") or []) or "N/A"
    cwe = record.get("cwe_id") or "N/A"
    score = record.get("base_score")
    score_str = f"{score}" if score is not None else "N/A"

    return (
        f"CVE ID: {record['cve_id']}. "
        f"Severity: {record.get('severity', 'N/A')} (score: {score_str}). "
        f"Attack Vector: {record.get('attack_vector', 'N/A')}. "
        f"CWE: {cwe}. "
        f"Status: {record.get('vuln_status', 'N/A')}. "
        f"Affected Products: {products}. "
        f"Description: {record.get('description', '')}"
    )


# ── Step 3: 임베딩 및 FAISS 인덱스 저장 ───────────────────
def build_index():
    # 1. 데이터 로드
    print(f"[1/4] 데이터 로드: {INPUT_PATH}")
    with open(INPUT_PATH, encoding="utf-8") as f:
        raw = json.load(f)
    records = raw["data"]
    print(f"      → {len(records):,}개 CVE 레코드")

    # 2. 텍스트 직렬화
    print("[2/4] 텍스트 직렬화 중...")
    texts = [serialize_cve(r) for r in records]
    cve_ids = [r["cve_id"] for r in records]

    # 직렬화 결과 샘플 출력
    print(f"\n      [샘플 직렬화 결과]\n      {texts[0]}\n")

    # 3. 임베딩 모델 로드 및 변환
    print(f"[3/4] 임베딩 모델 로드: {MODEL_NAME}")
    model = SentenceTransformer(MODEL_NAME)
    print(f"      → 임베딩 차원: {model.get_sentence_embedding_dimension()}")

    print(f"      배치 크기 {BATCH_SIZE}로 임베딩 변환 중...")
    embeddings = model.encode(
        texts,
        batch_size=BATCH_SIZE,
        show_progress_bar=True,
        normalize_embeddings=True,   # cosine similarity를 내적으로 사용 가능
        convert_to_numpy=True,
    )
    print(f"      → 임베딩 행렬 shape: {embeddings.shape}")

    # 4. FAISS 인덱스 구성 및 저장
    print("[4/4] FAISS 인덱스 구성 및 저장 중...")
    dim = embeddings.shape[1]

    # normalize_embeddings=True 이므로 내적(IP) == cosine similarity
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings.astype(np.float32))
    print(f"      → 인덱스 내 벡터 수: {index.ntotal:,}")

    faiss.write_index(index, FAISS_INDEX_PATH)
    print(f"      → FAISS 인덱스 저장: {FAISS_INDEX_PATH}")

    # CVE ID 매핑 저장 (검색 결과 → CVE ID 역참조용)
    with open(ID_MAP_PATH, "w", encoding="utf-8") as f:
        json.dump(cve_ids, f, ensure_ascii=False)
    print(f"      → ID 매핑 저장: {ID_MAP_PATH}")

    print("\n완료.")
    return index, cve_ids, embeddings


# ── 간단한 검색 테스트 ──────────────────────────────────────
def search_demo(query: str, index, cve_ids: list, model, top_k: int = 5):
    """임베딩된 인덱스에서 의미 기반 검색 데모."""
    q_vec = model.encode([query], normalize_embeddings=True, convert_to_numpy=True)
    scores, indices = index.search(q_vec.astype(np.float32), top_k)

    print(f"\n쿼리: \"{query}\"")
    print(f"{'순위':<4} {'CVE ID':<20} {'유사도':>8}")
    print("-" * 36)
    for rank, (idx, score) in enumerate(zip(indices[0], scores[0]), 1):
        print(f"{rank:<4} {cve_ids[idx]:<20} {score:>8.4f}")


if __name__ == "__main__":
    index, cve_ids, embeddings = build_index()

    # 검색 테스트
    model = SentenceTransformer(MODEL_NAME)
    search_demo("SQL injection in web application", index, cve_ids, model)
    search_demo("remote code execution critical severity", index, cve_ids, model)
    search_demo("buffer overflow memory corruption", index, cve_ids, model)
