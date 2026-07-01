# ScanOps 보안 모델 V13 — 배포 안내 (인프라 담당)

학습·GGUF 변환은 **이미 끝났습니다.** 이 폴더의 파일 2개만 서버에 올려서 `ollama create`로
등록하면 끝입니다. (모델 학습 필요 없음.)

## 폴더 내용
| 파일 | 크기 | 설명 |
|---|---|---|
| `v13_7b_lora.gguf` | 39MB | 우리가 파인튜닝한 **LoRA 어댑터**(보안 특화 부분만). 베이스 모델은 아래에서 받음. |
| `Modelfile` | — | Ollama 등록 설정. 베이스 + 어댑터를 합쳐 서빙(병합 아님, ADAPTER 방식). |

## 전제조건
- 서버에 **Ollama** 설치 (`curl -fsSL https://ollama.com/install.sh | sh`)
- 디스크 여유 ~5GB (베이스 모델 4.7GB + 어댑터 39MB)
- RAM ~6GB 이상 (7B Q4, CPU 서빙 가능 — GPU 불필요)

## 배포 3단계
```bash
# 1) 베이스 모델 받기 (한 번만, ~4.7GB)
ollama pull qwen2.5-coder:7b-instruct

# 2) 이 폴더에서 우리 모델 등록 (베이스 + 어댑터)
cd <이 폴더>
ollama create qwen2.5-coder-security-v13-7b -f Modelfile

# 3) 확인
ollama list | grep security-v13
```

## 동작 확인 (스모크 테스트)
```bash
ollama run qwen2.5-coder-security-v13-7b "Analyze this Python code for security vulnerabilities:
\`\`\`python
q = 'SELECT * FROM users WHERE id=' + request.args.get('id')
cursor.execute(q)
\`\`\`
Respond starting with VULNERABILITY:"
```
→ `VULNERABILITY: ...` (취약으로 판정) 나오면 정상. (안전한 파라미터화 쿼리를 넣으면 `VULNERABILITY: NONE`)

## 백엔드 연동
- Ollama API: `http://<서버>:11434` (기본 포트).
- 호출 엔드포인트: `POST /api/chat` (모델명 `qwen2.5-coder-security-v13-7b`).
- 백엔드(Spring Boot AiRouter)에서 `CUSTOM` 엔진의 `OLLAMA_URL` / 모델명을 위 값으로 설정.
- 서빙 파라미터(temperature=0 등)는 Modelfile에 내장돼 있어 별도 설정 불필요.

## 참고
- 이건 **어댑터 방식**이라 베이스 모델(`qwen2.5-coder:7b-instruct`)이 서버에 있어야 함.
  베이스는 공개 모델이라 `ollama pull`로 받으면 됨. 우리 고유 부분은 39MB 어댑터뿐.
- 재배포/롤백: 어댑터 파일만 교체하고 `ollama create` 다시 실행하면 됨.
- 모델 업데이트(V14 등) 시에도 이 폴더의 `.gguf`만 새 걸로 바꿔주면 동일 절차.
