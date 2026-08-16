#!/bin/bash
# CTX-1 안전장치: 시작 후 3시간(10800초) 뒤 계정의 모든 RunPod pod 강제 종료.
# 예산 상한 $6 / A40 $0.44/hr 기준 3시간 = $1.32 → 상한 한참 아래에서 확실히 끊는다.
KEY=$(grep RUNPOD_API_KEY /Users/kimsehan/Desktop/scanops/scanops-model/.env | cut -d= -f2)
sleep 10800
echo "CTX_KILLSWITCH FIRED $(date)"
for id in $(curl -s -H "Authorization: Bearer $KEY" https://rest.runpod.io/v1/pods | python3 -c "import sys,json;[print(p['id']) for p in json.load(sys.stdin)]"); do
  echo "terminating pod $id"
  curl -s -X DELETE -H "Authorization: Bearer $KEY" "https://rest.runpod.io/v1/pods/$id"
done
echo "CTX_KILLSWITCH DONE $(date)"
