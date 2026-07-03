#!/bin/zsh
# 밤샘 작업 (2026-07-03): ①증류 라벨 → ②v16.2 데이터 빌드 → ③자기일관성 벤치
# 로그: reports/overnight_v16.log
set -x
cd "$(dirname "$0")/.."
PY=.venv/bin/python
export PYTHONUNBUFFERED=1

echo "===== ① 증류 라벨 (v13·v14 교사, 안전 후보만) ====="
$PY scripts/distill_v15_labels.py

echo "===== ② v16.2 학습셋 빌드 (증류 필터 반영) ====="
cp data/lora_train_v16.jsonl data/lora_train_v16.jsonl.v16_1_bak
cp data/lora_train_v16_val.jsonl data/lora_train_v16_val.jsonl.v16_1_bak
$PY -m ml.build_dataset_v16 --stage build

echo "===== ③ v16.1 자기일관성 (k=3, temp 0.6) 4벤치 ====="
$PY scripts/benchmark_selfconsistency.py --model qwen2.5-coder-security-v16-1-7b:latest --k 3 --temp 0.6

echo "===== 완료 ====="
