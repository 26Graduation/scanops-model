#!/bin/bash
# V3 자율실행 안전장치: 시작 후 6시간 30분(23400초) 뒤 모든 RunPod pod 강제 종료
# 시작: 2026-08-13 (nohup으로 detach 실행)
KEY=$(grep RUNPOD_API_KEY /Users/kimsehan/Desktop/scanops/scanops-model/.env | cut -d= -f2)
sleep 23400
echo "KILLSWITCH FIRED $(date)"
for id in $(curl -s -H "Authorization: Bearer $KEY" https://rest.runpod.io/v1/pods | python3 -c "import sys,json;[print(p['id']) for p in json.load(sys.stdin)]"); do
  echo "terminating pod $id"
  curl -s -X DELETE -H "Authorization: Bearer $KEY" "https://rest.runpod.io/v1/pods/$id"
done
echo "KILLSWITCH DONE $(date)"
