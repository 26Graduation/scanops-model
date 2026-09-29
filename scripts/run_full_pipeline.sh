#!/usr/bin/env bash
# ScanOps QLoRA v2 전체 파이프라인 — 학습 완료 후 자동 실행
set -e
cd "$(dirname "$0")/.."

echo "========================================"
echo "  ScanOps QLoRA v2 파이프라인 시작"
echo "========================================"

source .venv/bin/activate

echo "[1] Gap-fill 데이터 추가 학습..."
python3 scripts/topup_train.py

echo "[2] GGUF 변환 + Ollama 등록..."
python3 scripts/convert_to_gguf_v2.py

echo "[3] 벤치마크 실행..."
python3 scripts/benchmark_qwen_rag.py

echo ""
echo "========================================"
echo "  파이프라인 완료!"
echo "========================================"
