#!/bin/bash
# V4 세션 킬스위치: 무장 후 5.5시간(19800초) 뒤 계정의 모든 RunPod pod 강제 종료.
# 근거: A100 $1.59/hr × 5.5h = $8.75 < 세션 상한 $15. pod 내부 워치독(8h)보다 먼저 닿는다.
KEY=$(grep RUNPOD_API_KEY /Users/kimsehan/Desktop/scanops/scanops-model/.env | cut -d= -f2)
echo "V4_KILLSWITCH ARMED $(date) fires_in=19800s"
sleep 19800
echo "V4_KILLSWITCH FIRED $(date)"
for id in $(curl -s -H "Authorization: Bearer $KEY" https://rest.runpod.io/v1/pods | python3 -c "import sys,json;[print(p['id']) for p in json.load(sys.stdin)]"); do
  echo "terminating pod $id"
  curl -s -X DELETE -H "Authorization: Bearer $KEY" "https://rest.runpod.io/v1/pods/$id"
done
echo "V4_KILLSWITCH DONE $(date)"
