#!/bin/bash
# Qwen2.5-Coder-7B-Instruct 베이스 모델 비교 실험: 학습 → test 채점
# 기존 out/adapter/(Qwen3.5-9B), out/test_report.json, out/test_predictions.jsonl은 건드리지 않음.
# 사용: nohup bash run_qwen25coder7b.sh > run_qwen25coder7b.log 2>&1 &
cd /workspace/rebuild
export HF_HOME=/workspace/hf
PIP="pip install -q --break-system-packages"

echo "Q25C7B_START $(date)"

# ── 환경 ──
# flash-linear-attention/causal-conv1d는 Qwen3.5-9B(하이브리드 선형어텐션)에만 필요한 커널이라
# Qwen2.5-Coder-7B(표준 dense 아키텍처)에는 불필요 — 설치 안 함 (설치 시도 시 causal-conv1d가
# torch의 최신 cu130 빌드와 이미지의 nvcc 12.4가 불일치해 소스 빌드 실패함)
$PIP unsloth || { echo "Q25C7B_FAIL_UNSLOTH"; exit 1; }
echo "Q25C7B_INSTALL_DONE $(date)"

# ── 학습 (GPU 시간 계산용으로 시작/끝 타임스탬프를 로그에 남김) ──
TRAIN_START=$(date +%s)
echo "Q25C7B_TRAIN_START_TS $TRAIN_START"
python train_qlora_qwen25coder7b.py > train_qwen25coder7b.log 2>&1 \
  && echo "Q25C7B_TRAIN_DONE $(date)" || { echo "Q25C7B_FAIL_TRAIN"; exit 1; }
TRAIN_END=$(date +%s)
echo "Q25C7B_TRAIN_END_TS $TRAIN_END"
echo "Q25C7B_TRAIN_ELAPSED_SEC $((TRAIN_END - TRAIN_START))"

# ── test 채점 (기존 test.jsonl 1,197건 그대로) ──
python eval_test_qwen25coder7b.py > eval_qwen25coder7b.log 2>&1 \
  && echo "Q25C7B_EVAL_DONE $(date)" || { echo "Q25C7B_FAIL_EVAL"; exit 1; }

echo "Q25C7B_ALL_DONE $(date)"
