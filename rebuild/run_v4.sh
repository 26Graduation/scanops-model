#!/bin/bash
# ScanOps V4-TRAIN — 수렴 학습 (사양서 rebuild/V4_TRAIN_RUN_SPEC.md)
#   학습(2 epoch, lr 1e-4) → logprob 채점 → greedy 채점 → tar → 회수 유예 후 자폭
#
# v3 대비 달라진 점 (사양서 §3):
#   - LEARNING_RATE 1e-4 (v3 는 2e-4)
#   - MAX_EPOCHS 2 완주 (v3 는 761 step 에서 시간 예산으로 중단)
#   - self-consistency 채점을 돌리지 않는다 — 오늘 SC-THRESHOLD-ONLY 로
#     단일 forward 대비 신호 이득이 관측되지 않았다(out/SC_INFO_RESULTS.md). 비용만 든다.
#
# 사용: nohup bash run_v4.sh > run_v4.log 2>&1 &
cd /workspace/rebuild
export HF_HOME=/workspace/hf

TAG=${TAG:-v4_r16_s42_lr1e4}     # 어댑터/체크포인트 디렉터리명
STAG=${STAG:-v4s42}              # 채점 산출물 접두사 (v3s42 관례 승계)
GRACE=${GRACE:-1800}             # 회수 유예: 정상 종료 후 이 시간만큼 살려두고 자폭

echo "V4_START $(date) TAG=$TAG STAG=$STAG"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader

# ── 학습 ────────────────────────────────────────────────────────────────────
LEARNING_RATE=1e-4 MAX_EPOCHS=2 SEED=42 LORA_RANK=16 OUT_NAME=$TAG \
  python train_qlora_v3.py > train_$TAG.log 2>&1 \
  && echo "V4_TRAIN_DONE $(date)" || echo "V4_FAIL_TRAIN $(date)"

ADP=out/$TAG
[ -d "$ADP" ] || ADP=$(ls -d out/checkpoints_$TAG/checkpoint-* 2>/dev/null | sort -t- -k2 -n | tail -1)
echo "USING_ADAPTER $ADP"

# ── ① logprob 연속점수 — AUC(주 지표)의 근거 ────────────────────────────────
python score_logprob.py "$ADP" "$STAG" \
  primevul_tune primevul_report cleanvul_v2_tune cleanvul_v2_report test \
  > logprob_$TAG.log 2>&1 && echo "V4_LOGPROB_DONE $(date)" || echo "V4_FAIL_LOGPROB $(date)"

# ── ② greedy 채점 — F1/운영점 표용 ──────────────────────────────────────────
python eval_v3.py "$ADP" "$STAG" greedy 1 test primevul_report cleanvul_v2_report \
  > greedy_$TAG.log 2>&1 && echo "V4_GREEDY_DONE $(date)" || echo "V4_FAIL_GREEDY $(date)"

# ── 회수용 묶음 (어댑터 제외 — 별도 회수) ───────────────────────────────────
tar czf /workspace/${TAG}_out.tgz out/${STAG}_*.json out/${STAG}_*.jsonl *_$TAG.log 2>/dev/null
ls -la /workspace/${TAG}_out.tgz
echo "V4_ALL_DONE $(date)"

# ── 정상 종료 경로의 자폭 (사양서 §5) ───────────────────────────────────────
echo "SELF_DESTRUCT_IN ${GRACE}s $(date)"
sleep $GRACE
curl -s -X DELETE -H "Authorization: Bearer $RUNPOD_API_KEY" \
  "https://rest.runpod.io/v1/pods/$RUNPOD_POD_ID"
