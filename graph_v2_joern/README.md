# graph_v2_joern — 로컬 실험용 (git에 커밋 안 함)

기존 `scanops/core/{code_graph,java_graph,multi_graph}.py`(정규식 기반)를 대체할 수 있는지
Joern(진짜 CPG 엔진) 기반 접근을 로컬에서 테스트해보는 프로토타입.
아직 서비스 코드 어디에도 연결 안 됨. 실험 전용.

## 배경

팀 계획 문서(§6-B, §7)에서 지적한 문제: 자체 정규식 그래프가 juice-shop에서 0건 탐지.
→ IRIS(ICLR 2025)/CPGHunter(EMSE 2026) 방식(LLM이 레포별 source/sink 스펙을 자동 생성)을
   차용해서, Joern + LLM 라벨링으로 다시 시도.

## 지금까지 확인된 것 (2026-08-20, 2차 갱신)

1. **Joern 엔진 자체는 작동한다.** juice-shop 백엔드(189파일)로 CPG 생성 성공,
   `reachableByFlows()`로 실제 SQL Injection 2건(V1, V2)을 서로 다른 파일에서 독립적으로 추적 성공.
2. **★ 진짜 cross-file 케이스도 확인됨 (V3).** `find_crossfile_candidates.sc`로 "다른 파일 함수를
   호출하는 지점"을 자동 탐색 → juice-shop의 실제 XXE 취약점(`routes/fileUpload.ts`가 업로드된 XML을
   `lib/xml.ts`의 `parseXmlString()`에 넘김)을 발견 → taint 경로가 실제로 **파일 경계를 넘어서**
   (`fileUpload.ts:76` → `xml.ts:33`) 추적됨을 확인(15개 경로). 이게 그래프의 핵심 존재 이유를
   처음으로 실증한 사례.
3. **API 후보 자동 추출은 된다.** `extract_candidates.sc`가 정규식/사람 개입 없이
   CPG에서 720개 서로 다른 호출을 뽑아냄 (노이즈 필터링만 적용, 어떤 게 위험한지는 모름).
4. **"위험한지 판단하는" 라벨링은 아직 자동화 안 됨.** 이번엔 Claude가 720개 후보를
   직접 검토해서 라벨을 붙였음(`specs/juiceshop_labeled_spec.json`).
   실제 서비스라면 이 단계가 LLM API 호출로 자동 실행돼야 함 — 미구현.
   (이 세션에서 API 키가 없어 시도 못 함 — 실제 API 키 확보가 다음 전제조건.)
5. **sanitizer 체크 로직 추가함 (`judge_with_sanitizer.sc`).** 기존엔 "경로가 있으면 무조건 취약"으로만
   판정했는데, 경로 중간에 안전처리 함수가 있으면 safe로 바꾸는 판정 함수를 만듦.
   **단, 한계 발견**: `redirect.ts`의 `isRedirectAllowed()`처럼 값을 안 바꾸고 if문으로만 막는
   "제어흐름 가드"는 이 방식으로 못 잡음 (값 자체를 세탁하는 sanitizer만 잡힘). 별도 보완 필요.

## 폴더 구조

```
scripts/
  extract_candidates.sc          ← ① CPG에서 API 후보 720개 자동 추출
  find_crossfile_candidates.sc   ← ★ "다른 파일 함수 호출" 지점을 자동으로 찾아줌 (131건 발견)
  taint_test.sc                  ← ② V1(login.ts) 취약점 추적 질의
  taint_test2_dbschema.sc        ← ② V2(dbSchemaChallenge_1.ts) 취약점 추적 질의
  taint_test3_crossfile_xxe.sc   ← ★ V3(fileUpload.ts→xml.ts) 진짜 cross-file 추적 질의
  judge_with_sanitizer.sc        ← sanitizer 유무까지 반영하는 재사용 가능한 판정 함수(judge())
specs/
  candidates_raw.json            ← ①의 결과물 (720개 후보 원본)
  juiceshop_labeled_spec.json    ← 사람이 라벨링한 결과 (V1/V2/V3 + 미검증 후보 3개)
cpg_cache/                       ← (비어있음, .gitignore로 CPG bin 제외)
```

Joern 프로그램 본체·juice-shop 클론·생성된 CPG 파일은 용량이 커서 이 레포 밖
`C:\Users\user\Desktop\graph-experiment\`에 따로 둠. `run_joern.sh`가 그 폴더에 있고,
JAVA_HOME/PATH/인코딩 설정을 매번 안 해도 되게 감싸둔 공통 실행 스크립트임
(`./run_joern.sh <스크립트경로>`로 실행).

## 재현 방법 (순서대로)

```bash
cd /c/Users/user/Desktop/graph-experiment
./run_joern.sh "<경로>/extract_candidates.sc"           # 후보 추출
./run_joern.sh "<경로>/find_crossfile_candidates.sc"     # cross-file 후보 탐색
./run_joern.sh "<경로>/taint_test3_crossfile_xxe.sc"      # cross-file 취약점 추적
./run_joern.sh "<경로>/judge_with_sanitizer.sc"           # sanitizer 반영 최종 판정
```

## 안 된 것 (다음에 할 일)

- [ ] 라벨링을 실제 LLM API 호출로 자동화 (이번 세션엔 API 키가 없어서 못 함 — 다음 전제조건)
- [ ] 제어흐름 가드(if문 방식 검증, `isRedirectAllowed` 같은 것)를 sanitizer로 인식하는 로직 추가
- [ ] CPGHunter 방식: 외부 라이브러리(sequelize 등)의 오염 전파 규칙 자동 생성
- [ ] 라인 단위 채점기 (지금은 사람이 눈으로 경로 확인) — juice-shop 44건 정답 중 3건만 확인됨
- [ ] Python/Java/PHP/C·C++ 다른 언어 프론트엔드 테스트
- [ ] 실제 scanops 서비스(api_rebuild.py)에 연결, 모델 판정이랑 합치는 로직
