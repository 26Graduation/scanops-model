#!/usr/bin/env bash
# Tier A+B 38개 CWE(스킵 7개 제외)를 각자 자기 디렉터리에 대해 순서대로 돌린다.
# 각 실행은 spec.tsv 전체(62개 sink 룰)를 로드하지만, 그 CWE 자기 디렉터리에 없는 API 패턴은
# candidate sink 자체가 0개라 비용이 거의 안 든다 (CWE-89 샘플런에서 실측 확인됨).
set -uo pipefail

JJ=/Users/kimsehan/Desktop/scanops/scanops-model/benchmarks/juliet-java
JULIET="$JJ/juliet-source/src/testcases"
SPEC="$JJ/spec_juliet_java_tier_ab_v1.tsv"
SANFILE="$JJ/sanitizers_javasrc.tsv"
QUERIES=/Users/kimsehan/Desktop/scanops/scanops-model/joern/queries
# 2026-09-05 3라운드 §6 재실행: out/(1-7 sanitizer 미연동) 과 out_v2_sanitizer/(2라운드)
# 둘 다 보존한다. 이번엔 CWE-113 sanitizer 카테고리 보강 + CWE-477 arity 메커니즘이 새로
# 들어간 최종 spec.tsv/sanitizers_javasrc.tsv 로 38개 전부 다시 돌려서 out_v3/ 에 쓴다.
OUT="${JULIET_OUT:-$JJ/out_v3}"
SRC_MODE="${JULIET_SRC_MODE:-params}"
TIMING_LOG="$OUT/run_all_timing.tsv"
if [ -e "$TIMING_LOG" ]; then
  echo "REFUSE: run output already exists: $TIMING_LOG" >&2
  exit 2
fi
mkdir -p "$OUT"
echo -e "cwe\tdir\tn_files\tseconds\texit_code" > "$TIMING_LOG"

# cwe_id -> dirname (find-sec-bugs juliet-test-suite 실제 디렉터리명)
# macOS 기본 Bash 3도 정수 CWE 인덱스를 지원한다. 연관배열(-A)은 Bash 4 전용이므로
# sparse indexed array를 사용한다.
declare -a DIRS=(
  [23]="CWE23_Relative_Path_Traversal"
  [36]="CWE36_Absolute_Path_Traversal"
  [78]="CWE78_OS_Command_Injection"
  [80]="CWE80_XSS"
  [81]="CWE81_XSS_Error_Message"
  [83]="CWE83_XSS_Attribute"
  [89]="CWE89_SQL_Injection"
  [90]="CWE90_LDAP_Injection"
  [113]="CWE113_HTTP_Response_Splitting"
  [134]="CWE134_Uncontrolled_Format_String"
  [256]="CWE256_Plaintext_Storage_of_Password"
  [259]="CWE259_Hard_Coded_Password"
  [315]="CWE315_Plaintext_Storage_in_Cookie"
  [319]="CWE319_Cleartext_Tx_Sensitive_Info"
  [321]="CWE321_Hard_Coded_Cryptographic_Key"
  [470]="CWE470_Unsafe_Reflection"
  [601]="CWE601_Open_Redirect"
  [643]="CWE643_Xpath_Injection"
  [15]="CWE15_External_Control_of_System_or_Configuration_Setting"
  [114]="CWE114_Process_Control"
  [209]="CWE209_Information_Leak_Error"
  [327]="CWE327_Use_Broken_Crypto"
  [328]="CWE328_Reversible_One_Way_Hash"
  [329]="CWE329_Not_Using_Random_IV_with_CBC_Mode"
  [336]="CWE336_Same_Seed_in_PRNG"
  [338]="CWE338_Weak_PRNG"
  [378]="CWE378_Temporary_File_Creation_With_Insecure_Perms"
  [379]="CWE379_Temporary_File_Creation_in_Insecure_Dir"
  [382]="CWE382_Use_of_System_Exit"
  [477]="CWE477_Obsolete_Functions"
  [533]="CWE533_Info_Exposure_Server_Log"
  [534]="CWE534_Info_Exposure_Debug_Log"
  [539]="CWE539_Information_Exposure_Through_Persistent_Cookie"
  [598]="CWE598_Information_Exposure_QueryString"
  [698]="CWE698_Redirect_Without_Exit"
  [759]="CWE759_Unsalted_One_Way_Hash"
  [760]="CWE760_Predictable_Salt_One_Way_Hash"
  [526]="CWE526_Info_Exposure_Environment_Variables"
)

ORDER=(23 36 78 80 81 83 89 90 113 134 256 259 315 319 321 470 601 643 15 114 209 327 328 329 336 338 378 379 382 477 533 534 539 598 698 759 760 526)

for cwe in "${ORDER[@]}"; do
  dname="${DIRS[$cwe]}"
  indir="$JULIET/$dname"
  if [ ! -d "$indir" ]; then
    echo "SKIP CWE-$cwe: dir not found ($indir)"
    continue
  fi
  nfiles=$(find "$indir" -name "*.java" | wc -l | tr -d ' ')
  outfile="$OUT/cwe${cwe}.json"
  echo "=== CWE-$cwe ($dname, $nfiles files) ==="
  t0=$(date +%s)
  docker run --rm \
    --memory=8g \
    -e JAVA_OPTS="-Xmx6g" \
    -e _JAVA_OPTIONS="-Xmx6g" \
    -v "$JJ:$JJ" \
    -v "$QUERIES:/prod-queries:ro" \
    -w "$JJ" \
    ghcr.io/joernio/joern:master \
    joern --script /prod-queries/taint_spec.sc \
      --param inDir="$indir" \
      --param lang=JAVASRC \
      --param outFile="$outfile" \
      --param specFile="$SPEC" \
      --param sanFile="$SANFILE" \
      --param srcMode="$SRC_MODE" \
      --param arm="cwe${cwe}_r3" \
    > "$OUT/cwe${cwe}.log" 2>&1
  rc=$?
  t1=$(date +%s)
  dt=$((t1 - t0))
  echo -e "${cwe}\t${dname}\t${nfiles}\t${dt}\t${rc}" >> "$TIMING_LOG"
  echo "    -> ${dt}s, exit=${rc}"
done

echo "=== ALL DONE ==="
cat "$TIMING_LOG"
