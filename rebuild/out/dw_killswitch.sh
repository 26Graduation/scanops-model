#!/bin/bash
# DIFF-AWARE 세션 킬스위치: 무장 후 5시간(18000초) 뒤 계정의 모든 RunPod pod 강제 종료.
# 근거: 세션 상한 $12. A6000 $0.53/hr(Phase 1) + A100 $1.59/hr(Phase 2, 필요시)를
#       합쳐도 5시간이면 $10 아래에서 확실히 끊긴다.
KEY=$(grep RUNPOD_API_KEY /Users/kimsehan/Desktop/scanops/scanops-model/.env | cut -d= -f2)
echo "DW_KILLSWITCH ARMED $(date) fires_in=18000s"
sleep 18000
echo "DW_KILLSWITCH FIRED $(date)"
for id in $(curl -s -H "Authorization: Bearer $KEY" https://rest.runpod.io/v1/pods | python3 -c "import sys,json;[print(p['id']) for p in json.load(sys.stdin)]"); do
  echo "terminating pod $id"
  curl -s -X DELETE -H "Authorization: Bearer $KEY" "https://rest.runpod.io/v1/pods/$id"
done
echo "DW_KILLSWITCH DONE $(date)"
