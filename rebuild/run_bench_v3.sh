#!/bin/bash
# v3 벤치 배터리 — 정보량/분 이 높은 순서로 배치해서 중간에 끊겨도 쓸 게 남게 한다.
# 사용: ADP=out/checkpoints_v3_r16_s42/checkpoint-750 TAG=v3s42 bash run_bench_v3.sh
cd /workspace/rebuild
export HF_HOME=/workspace/hf
ADP=${ADP:?adapter path required}
TAG=${TAG:?tag required}
FULL=${FULL:-1}          # 0이면 저비용 세트만 (시드 재현성 검증용)

echo "BENCH_START $(date) ADP=$ADP TAG=$TAG"

# ① logprob 연속점수 — 5개 split, 건당 ~0.18s. AUC·임계값 전부 여기서 나온다.
python score_logprob.py $ADP $TAG val_v3 primevul_tune primevul_report cleanvul_v2_tune cleanvul_v2_report test \
  > lp_$TAG.log 2>&1 && echo "BENCH_LOGPROB_DONE $(date)" || echo "BENCH_FAIL_LOGPROB"

# ② 내부 test greedy — MUST-1 표제 숫자 + CWE/SEV(STRETCH)
python eval_v3.py $ADP $TAG greedy 1 test > gt_$TAG.log 2>&1 \
  && echo "BENCH_GREEDY_TEST_DONE $(date)" || echo "BENCH_FAIL_GREEDY_TEST"

if [ "$FULL" = "1" ]; then
  # ③ PrimeVul greedy (360건, 쌈)
  python eval_v3.py $ADP $TAG greedy 1 primevul_tune primevul_report > gp_$TAG.log 2>&1 \
    && echo "BENCH_GREEDY_PV_DONE $(date)" || echo "BENCH_FAIL_GREEDY_PV"
  # ④ self-consistency k=5 (투표 임계는 tune에서)
  python eval_v3.py $ADP $TAG sample 5 primevul_tune primevul_report cleanvul_v2_tune \
    > sc_$TAG.log 2>&1 && echo "BENCH_SC_DONE $(date)" || echo "BENCH_FAIL_SC"
  # ⑤ CleanVul greedy 2,706건 — 제일 비싸서 마지막
  python eval_v3.py $ADP $TAG greedy 1 cleanvul_v2_report > gc_$TAG.log 2>&1 \
    && echo "BENCH_GREEDY_CV_DONE $(date)" || echo "BENCH_FAIL_GREEDY_CV"
fi

tar czf /workspace/${TAG}_bench.tgz out/${TAG}_* out/v3_*.json *.log 2>/dev/null
echo "BENCH_ALL_DONE $(date)"
