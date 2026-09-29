#!/bin/bash
# v2 전체 파이프라인: 환경설치 → QLoRA 학습(train_v2) → 내부 test → 외부 test 3종
# 사용: nohup bash run_v2.sh > run_v2.log 2>&1 &
cd /workspace/rebuild
export HF_HOME=/workspace/hf
PIP="pip install -q --break-system-packages"

echo "V2_START $(date)"

# ── 환경 (기존 pod와 동일 스택) ──
$PIP unsloth || { echo "V2_FAIL_UNSLOTH"; exit 1; }
$PIP flash-linear-attention || { echo "V2_FAIL_FLA"; exit 1; }
$PIP ninja packaging && $PIP --no-build-isolation causal-conv1d || { echo "V2_FAIL_KERNELS"; exit 1; }
echo "V2_INSTALL_DONE $(date)"

# ── 학습: train_v2/val_v2 (환경변수로 스플릿 지정) ──
# v1 어댑터를 덮어쓰기 전에 백업 (롤백 안전장치)
[ -d out/adapter ] && [ ! -d out/adapter_v1 ] && cp -r out/adapter out/adapter_v1
TRAIN_SPLIT=train_v2 VAL_SPLIT=val_v2 python train_qlora.py > train_v2.log 2>&1 \
  && echo "V2_TRAIN_DONE $(date)" || { echo "V2_FAIL_TRAIN"; exit 1; }

# ── 내부 test (기존 test.jsonl 고정 — v1과 같은 자) ──
python eval_test.py > eval_v2_internal.log 2>&1 \
  && echo "V2_INTERNAL_DONE $(date)" || { echo "V2_FAIL_INTERNAL"; exit 1; }
cp out/test_report.json out/v2_internal_report.json
cp out/test_predictions.jsonl out/v2_internal_predictions.jsonl

# ── 외부 test 3종 (PrimeVul paired / CleanVul v2 held-out) ──
# eval_external.py는 인자로 {name}_test.jsonl을 읽음 → cleanvul_v2도 같은 규칙
for NAME in primevul cleanvul_v2; do
  python eval_external.py $NAME > eval_v2_$NAME.log 2>&1 \
    && echo "V2_EXT_${NAME}_DONE $(date)" || { echo "V2_FAIL_EXT_$NAME"; exit 1; }
done

echo "V2_ALL_DONE $(date)"
