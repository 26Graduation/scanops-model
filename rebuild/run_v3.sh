#!/bin/bash
# ScanOps v3 전체 파이프라인 (pod 안에서 실행)
#   학습 → greedy 채점 3종 → logprob 점수 → self-consistency → 산출물 tar → pod 자폭
# 사용: nohup bash run_v3.sh > run_v3.log 2>&1 &
cd /workspace/rebuild
export HF_HOME=/workspace/hf

TAG=${TAG:-v3_r16_s42}
GRACE=${GRACE:-1800}     # 회수 유예: 정상 종료 후 이 시간만큼 살려두고 자폭

echo "V3_START $(date) TAG=$TAG"

OUT_NAME=$TAG python train_qlora_v3.py > train_$TAG.log 2>&1 \
  && echo "V3_TRAIN_DONE $(date)" || { echo "V3_FAIL_TRAIN"; }

ADP=out/$TAG
[ -d "$ADP" ] || ADP=$(ls -d out/checkpoints_$TAG/checkpoint-* 2>/dev/null | sort -t- -k2 -n | tail -1)
echo "USING_ADAPTER $ADP"

# ① logprob 연속점수 (가장 쌈) — 임계값 스윕용
python score_logprob.py $ADP $TAG primevul_tune primevul_report cleanvul_v2_tune cleanvul_v2_report test \
  > logprob_$TAG.log 2>&1 && echo "V3_LOGPROB_DONE $(date)" || echo "V3_FAIL_LOGPROB"

# ② greedy 채점 (표에 올라갈 기본 운영점)
python eval_v3.py $ADP $TAG greedy 1 test primevul_report primevul_tune cleanvul_v2_tune cleanvul_v2_report \
  > greedy_$TAG.log 2>&1 && echo "V3_GREEDY_DONE $(date)" || echo "V3_FAIL_GREEDY"

# ③ self-consistency k=5 (투표 임계 t는 tune에서 고름)
python eval_v3.py $ADP $TAG sample 5 primevul_tune primevul_report cleanvul_v2_tune \
  > sc_$TAG.log 2>&1 && echo "V3_SC_DONE $(date)" || echo "V3_FAIL_SC"

tar czf /workspace/${TAG}_out.tgz out/*.json out/*.jsonl *.log 2>/dev/null
echo "V3_ALL_DONE $(date)"

# 정상 종료 경로의 자폭 (회수 유예 후) — 사양서 §7
sleep $GRACE
curl -s -X DELETE -H "Authorization: Bearer $RUNPOD_API_KEY" \
  "https://rest.runpod.io/v1/pods/$RUNPOD_POD_ID"
