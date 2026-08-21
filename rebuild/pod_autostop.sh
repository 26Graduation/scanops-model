#!/bin/bash
# ScanOps v2(line) — 파드 자립 마무리 스크립트 (파드 안에서 실행).
#
# 목적: 사용자가 노트북을 덮어도 파드가 스스로 마무리하고 **GPU 과금을 끊게** 한다.
#   1) 런북(학습 + score_logprob)이 끝날 때까지 대기
#   2) 회수 유예(GRACE) 만큼 기다린다 — 사용자가 그 사이 돌아오면 그냥 이어서 쓰면 된다
#   3) RunPod `podStop` 호출 — **terminate 가 아니다.**
#      stop 은 /workspace 볼륨을 보존한 채 GPU 과금만 중단한다. 그래서 산출물을
#      외부로 내보낼 필요가 없고, 나중에 resume 해서 그대로 회수하면 된다.
#      (terminate 는 볼륨째 삭제라 어댑터를 잃는다 — 절대 쓰지 않는다.)
#
# v1 의 run_v3.sh / run_v4.sh 가 쓰던 "회수 유예 후 자폭" 관례를 따르되,
# 자폭(terminate)을 자기정지(stop)로 바꿔 데이터 손실 위험을 없앴다.
#
# 키는 인자로 받지 않고 /workspace/.podenv 파일에서 읽는다 (셸 히스토리·프로세스 목록에
# 남기지 않기 위해).
#
# 실행: nohup bash /workspace/rebuild/pod_autostop.sh > /workspace/autostop.log 2>&1 &
set -u

GRACE=${GRACE:-1800}          # 런북 종료 후 이만큼 기다렸다가 정지 (기본 30분)
LOG=/workspace/run_v2line.log

# shellcheck disable=SC1091
. /workspace/.podenv        # RUNPOD_API_KEY, RUNPOD_POD_ID

echo "[autostop] 시작 $(date -u) / GRACE=${GRACE}s / pod=${RUNPOD_POD_ID}"

echo "[autostop] 런북 종료 대기…"
while ! grep -qE "V2LINE_ALL_DONE|V2LINE_FAIL_TRAIN|V2LINE_FAIL_PRECHECK" "$LOG" 2>/dev/null; do
  sleep 60
done
echo "[autostop] 런북 종료 감지 $(date -u)"
tail -6 "$LOG"

echo "[autostop] 산출물 확인"
ls -la /workspace/rebuild/out/ 2>/dev/null | head -20
du -sh /workspace/rebuild/out/adapter* 2>/dev/null

echo "[autostop] 회수 유예 ${GRACE}s 대기 (이 사이 사용자가 돌아오면 정지되기 전에 회수 가능)"
sleep "$GRACE"

echo "[autostop] podStop 호출 $(date -u) — 볼륨은 보존되고 GPU 과금만 멈춘다"
curl -s -X POST "https://api.runpod.io/graphql?api_key=${RUNPOD_API_KEY}" \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: scanops-v2line/1.0' \
  -d "{\"query\":\"mutation { podStop(input: {podId: \\\"${RUNPOD_POD_ID}\\\"}) { id desiredStatus } }\"}"
echo
echo "[autostop] 완료 $(date -u)"
