#!/bin/bash
# graph_v2_joern 실험 환경 재현 스크립트 (Git Bash에서 실행)
# 새 컴퓨터(노트북 등)에서 이 스크립트 하나로 Joern + juice-shop + CPG까지 재구성한다.
# 이미 돼있는 단계는 자동으로 건너뛰므로 여러 번 실행해도 안전함(idempotent).
#
# 사용법: bash setup_env.sh
#
# 주의: Java 설치(1단계)는 winget이 필요해서 PowerShell에서 따로 해야 함.
#       이 스크립트는 자바가 이미 있는지만 확인하고, 없으면 설치 명령을 안내만 한다.

set -e
BASE="/c/Users/user/Desktop/graph-experiment"
JAVA_HOME_PATH="/c/Program Files/Eclipse Adoptium/jdk-17.0.20.8-hotspot"

echo "========== ① Java 17 확인 =========="
if [ -d "$JAVA_HOME_PATH" ]; then
  echo "OK — 이미 설치돼 있음: $JAVA_HOME_PATH"
else
  echo "!! Java 17이 없습니다. PowerShell에서 아래 명령을 먼저 실행하세요:"
  echo ""
  echo "   winget install --id EclipseAdoptium.Temurin.17.JDK -e --source winget --accept-package-agreements --accept-source-agreements --silent"
  echo ""
  echo "   설치 경로가 다르면 이 스크립트 상단의 JAVA_HOME_PATH 값도 맞게 고쳐야 함."
  exit 1
fi

export JAVA_HOME="$JAVA_HOME_PATH"
export PATH="$JAVA_HOME/bin:$PATH"
export JAVA_TOOL_OPTIONS="-Dfile.encoding=UTF-8"

mkdir -p "$BASE"
cd "$BASE"

echo ""
echo "========== ② Joern CLI 확인/설치 =========="
if [ -d "$BASE/joern-cli" ]; then
  echo "OK — 이미 설치돼 있음: $BASE/joern-cli"
else
  echo "다운로드 중 (약 1.7GB, 시간 걸림)..."
  curl -L -o joern-cli.zip "https://github.com/joernio/joern/releases/latest/download/joern-cli-windows-x86_64.zip"
  echo "압축 해제 중..."
  unzip -q joern-cli.zip
  rm -f joern-cli.zip
  echo "완료"
fi

echo ""
echo "========== ③ juice-shop 클론 확인 =========="
if [ -d "$BASE/juice-shop" ]; then
  echo "OK — 이미 클론돼 있음: $BASE/juice-shop"
else
  git clone --depth 1 https://github.com/juice-shop/juice-shop.git
fi

echo ""
echo "========== ④ CPG 생성 확인 =========="
if [ -f "$BASE/juiceshop.cpg.bin" ]; then
  echo "OK — 이미 있음: $BASE/juiceshop.cpg.bin"
else
  echo "CPG 생성 중 (juice-shop 백엔드, 1~2분)..."
  cd "$BASE/juice-shop"
  "$BASE/joern-cli/jssrc2cpg.bat" . --output ../juiceshop.cpg.bin \
    --exclude frontend --exclude node_modules --exclude test \
    --exclude cypress --exclude screenshots --exclude ftp \
    --exclude uploads --exclude i18n
  cd "$BASE"
fi

echo ""
echo "========== ⑤ run_joern.sh 공통 실행 스크립트 확인 =========="
if [ -f "$BASE/run_joern.sh" ]; then
  echo "OK — 이미 있음"
else
  cat > "$BASE/run_joern.sh" << 'WRAPPER'
#!/bin/bash
set -e
export JAVA_HOME="/c/Program Files/Eclipse Adoptium/jdk-17.0.20.8-hotspot"
export PATH="$JAVA_HOME/bin:$PATH"
export JAVA_TOOL_OPTIONS="-Dfile.encoding=UTF-8"
cd "/c/Users/user/Desktop/graph-experiment"
"./joern-cli/joern.bat" --script "$1" 2>&1 | grep -v "^\[INFO\]"
WRAPPER
  chmod +x "$BASE/run_joern.sh"
  echo "생성함"
fi

echo ""
echo "========== 준비 완료 =========="
echo "이제 이렇게 실행하면 됩니다:"
echo "  \"$BASE/run_joern.sh\" \"<이 레포>/graph_v2_joern/scripts/taint_test3_crossfile_xxe.sc\""
