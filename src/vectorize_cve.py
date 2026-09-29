"""
CVE 데이터를 BAAI/bge-small-en-v1.5 모델로 벡터화하여 FAISS 인덱스로 저장합니다.

출력:
  data/cve_index.faiss — FAISS 검색 인덱스
  메타데이터는 nvdcve-2.0-preprocessed.json을 그대로 사용 (별도 파일 없음)
"""

import json
import time
from pathlib import Path

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

DATA_DIR = Path(__file__).parent.parent / "data"
INPUT_PATH = DATA_DIR / "nvdcve-2.0-preprocessed.json"
INDEX_PATH = DATA_DIR / "cve_index.faiss"

MODEL_NAME = "BAAI/bge-small-en-v1.5"
BATCH_SIZE = 64


def build_embed_text(cve: dict) -> str:
    """임베딩에 사용할 텍스트를 구성합니다. bge 계열은 쿼리와 문서를 다르게 인코딩하므로
    문서(패시지) 쪽은 접두사 없이 내용 전체를 담습니다."""
    parts = [cve.get("description", "")]

    severity = cve.get("severity", "")
    score = cve.get("score")
    if severity or score is not None:
        parts.append(f"Severity: {severity} CVSS: {score}")

    cwes = cve.get("cwe", [])
    if cwes:
        parts.append("CWE: " + " ".join(cwes))

    return " ".join(filter(None, parts))


def main() -> None:
    print(f"[1/4] 데이터 로드: {INPUT_PATH}")
    with open(INPUT_PATH, encoding="utf-8") as f:
        cves = json.load(f)
    print(f"      {len(cves)}개 CVE 항목 로드 완료")

    print(f"\n[2/4] 모델 로드: {MODEL_NAME}")
    model = SentenceTransformer(MODEL_NAME)
    dim = model.get_sentence_embedding_dimension()
    print(f"      임베딩 차원: {dim}")

    print("\n[3/4] 벡터화 시작")
    texts = [build_embed_text(c) for c in cves]

    start = time.time()
    embeddings = model.encode(
        texts,
        batch_size=BATCH_SIZE,
        show_progress_bar=True,
        normalize_embeddings=True,  # bge 권장: L2 정규화 후 코사인 유사도 = 내적
        convert_to_numpy=True,
    )
    elapsed = time.time() - start
    print(f"      완료: {elapsed:.1f}초 ({len(cves) / elapsed:.0f} CVE/s)")

    embeddings = embeddings.astype(np.float32)

    print("\n[4/4] FAISS 인덱스 생성 및 저장")
    # 정규화된 벡터에서 내적 = 코사인 유사도
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)
    print(f"      인덱스 내 벡터 수: {index.ntotal}")

    faiss.write_index(index, str(INDEX_PATH))
    print(f"      저장: {INDEX_PATH}")

    print("\n완료.")
    print(f"  인덱스 크기: {INDEX_PATH.stat().st_size / 1024 / 1024:.1f} MB")
    print(f"  메타데이터: {INPUT_PATH} 를 그대로 사용")


if __name__ == "__main__":
    main()
