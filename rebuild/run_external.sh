#!/bin/bash
# 외부 벤치마크 야간 실행: 환경 설치 → PrimeVul(360건, ~15분) → CleanVul(11,580건, ~7시간)
# 새 pod는 pip 패키지가 비어 있으므로(네트워크 볼륨엔 /workspace만 유지) 설치부터 한다.
# 사용: nohup bash run_external.sh > run_external.log 2>&1 &
cd /workspace/rebuild
export HF_HOME=/workspace/hf   # 베이스 모델 캐시를 볼륨에 — pod 재생성 때 재다운로드 방지

echo "EXT_START $(date)"

# 학습/eval_test 때와 동일 스택. flash-linear-attention/causal-conv1d 없으면
# Qwen3.5 하이브리드 어텐션이 토큰당 ~18초로 느려짐 (기존 이슈 재발 방지)
# --break-system-packages: 이 이미지는 PEP 668로 시스템 pip을 막아둠 (run_night.sh와 동일 처리)
PIP="pip install -q --break-system-packages"
$PIP unsloth || { echo "EXT_FAIL_INSTALL_UNSLOTH"; exit 1; }
$PIP flash-linear-attention || { echo "EXT_FAIL_INSTALL_FLA"; exit 1; }
# causal-conv1d는 소스 빌드 — 빌드 격리를 끄지 않으면 격리 환경이 최신 torch(cu130)를
# 받아와 pod의 nvcc(12.8)와 버전 불일치로 컴파일이 깨진다. 설치된 torch(cu128)를 쓰게 한다.
$PIP ninja packaging
$PIP --no-build-isolation causal-conv1d || { echo "EXT_FAIL_INSTALL_KERNELS"; exit 1; }
echo "EXT_INSTALL_DONE $(date)"

python eval_external.py primevul > eval_primevul.log 2>&1 \
  && echo "EXT_PRIMEVUL_DONE $(date)" \
  || { echo "EXT_FAIL_PRIMEVUL"; exit 1; }

python eval_external.py cleanvul > eval_cleanvul.log 2>&1 \
  && echo "EXT_CLEANVUL_DONE $(date)" \
  || { echo "EXT_FAIL_CLEANVUL"; exit 1; }

echo "EXT_ALL_DONE $(date)"
