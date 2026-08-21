"""ScanOps v2(line) — MAX_SEQ_LEN 만 바꿔 train_qlora.py 를 실행하는 래퍼.

`train_qlora.py` 는 v1 FROZEN 이라 **파일을 수정하지 않는다** (§11·§13). 그런데 그 파일의
`MAX_SEQ_LEN` 은 모듈 상수라 환경변수 주입 경로가 없다. 그래서 원본을 디스크에서 읽어
**그 한 줄만 치환한 뒤 exec** 한다 — 원본 파일은 바이트 그대로 남는다.

바꾸는 것은 두 가지뿐이다:
  (1) MAX_SEQ_LEN 4096 → V2_MAX_SEQ_LEN (기본 16384)
  (2) MAX_EPOCHS 3 → V2_MAX_EPOCHS (기본 2)

BATCH_PER_DEVICE/GRAD_ACCUM 은 **원본 2×8 그대로** 둔다. 4×4(유효배치 동일)로 GPU 를 더
채워보는 처리량 최적화를 실제로 시도했으나, 정상상태 스텝시간이 배치2 ~110초 → 배치4 ~121초로
**오히려 나빠졌다**(실측). 원인은 시퀀스 길이 편차가 커서 배치가 클수록 패딩 낭비가 늘기 때문.
그래서 되돌렸고, 이 관측을 V2_RESULTS.md 후속 개선사항에 남긴다(길이 정렬 배칭/패킹이 답).

MAX_EPOCHS 를 줄인 이유(2026-08-21 사용자 결정): 16k 실측 스텝시간 ~121초 × 462스텝 = 15.5시간
이라 마감(08-22 09:00 KST)까지 평가·보고서 여유가 2.4시간뿐이었다. 2 epoch(308스텝)로 줄여
10.4시간에 끝내고 7.5시간을 남긴다. **v1 은 9,221샘플×3epoch÷16 ≈ 1,729스텝**을 돌았으므로
v2 의 308스텝은 학습량이 훨씬 적다 — ③ AUC 해석 시 이 차이를 반드시 병기해야 한다.
LORA_RANK/ALPHA/LEARNING_RATE/BATCH/GRAD_ACCUM/SEED 는 **원본 값 그대로** 쓴다.
치환 결과를 실행 전에 출력해서 무엇이 바뀌었는지 로그에 남긴다.

근거(2026-08-21 사용자 결정): v2 는 파일 단위 입력인데 4096 은 v1 이 함수 조각용으로 고른
값이었다. vuln 500건 표본 실측 — 정답 LINE 가시율 4k 68.4% / 16k 90.2%, C/C++ 는 41.1% → 75.0%.
이 변경으로 v1 대비 변수가 2개(입력단위 + 컨텍스트 예산)가 되므로 §12 "한 번에 한 변수"에서
벗어난다 → V2_RESULTS.md 에 그 사실과 해석 한계를 명시해야 한다.

실행: PYTHONPATH=/workspace/rebuild TRAIN_SPLIT=... VAL_SPLIT=... python run_train_v2line_16k.py
"""
import os, re, pathlib, sys

TARGET = int(os.environ.get("V2_MAX_SEQ_LEN", "16384"))
src_path = pathlib.Path(__file__).resolve().parent / "train_qlora.py"
src = src_path.read_text()

EPOCHS = int(os.environ.get("V2_MAX_EPOCHS", "2"))

subs = [(r"^MAX_SEQ_LEN = 4096", f"MAX_SEQ_LEN = {TARGET}"),
        (r"^MAX_EPOCHS = 3", f"MAX_EPOCHS = {EPOCHS}")]
new = src
for pat, rep in subs:
    new, n = re.subn(pat, rep, new, count=1, flags=re.M)
    if n != 1:
        print(f"[wrapper] 치환 실패: {pat} (n={n}) — 중단", flush=True)
        sys.exit(1)
print(f"[wrapper] {src_path.name} 원본은 무수정. 메모리에서만 치환:", flush=True)
print(f"[wrapper]   MAX_SEQ_LEN 4096 -> {TARGET}", flush=True)
print(f"[wrapper]   MAX_EPOCHS 3 -> {EPOCHS}", flush=True)
print("[wrapper]   BATCH_PER_DEVICE/GRAD_ACCUM 은 원본 2x8 유지 (4x4 는 실측상 더 느렸다)",
      flush=True)
for line in new.splitlines():
    if re.match(r"^(MODEL_ID|MAX_SEQ_LEN|LORA_RANK|LORA_ALPHA|LEARNING_RATE|MAX_EPOCHS|"
                r"EARLY_STOP_PATIENCE|BATCH_PER_DEVICE|GRAD_ACCUM|SEED) ", line):
        print(f"[wrapper]   {line}", flush=True)

g = {"__name__": "__main__", "__file__": str(src_path)}
exec(compile(new, str(src_path), "exec"), g)
