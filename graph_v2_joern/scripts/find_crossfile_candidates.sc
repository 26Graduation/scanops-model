// cross-file 후보 자동 탐색:
// "A파일에서 사용자입력을 받아서, B파일(다른 파일)의 함수를 호출하는" 지점을 자동으로 찾는다.
// 사람이 파일을 하나씩 읽는 대신, CPG의 호출관계(callee의 methodFullName)를 이용.

importCpg("C:/Users/user/Desktop/graph-experiment/juiceshop.cpg.bin")

// 내부 함수 호출(우리 코드 안의 다른 함수를 부르는 것)만 추림.
// 내부 호출은 methodFullName이 "파일경로::program:함수명" 형태로 시작함 (라이브러리 호출과 다름).
val internalCalls = cpg.call
  .filter(_.methodFullName.contains("::program:"))
  .l

println(s"내부 함수 호출 총 개수: ${internalCalls.size}")

// 호출하는 쪽 파일과, 실제 함수가 정의된 파일이 다른 것만 골라냄 = 진짜 cross-file
case class CrossFileCall(callerFile: String, calleeFile: String, calleeName: String,
                           callerLine: Int, code: String)

val crossFile = internalCalls.flatMap { c =>
  val callerFile = c.file.name.headOption.getOrElse("")
  // methodFullName 예: "routes\\login.ts::program:queryResultToJson" 에서 앞부분이 정의 파일
  val calleeFile = c.methodFullName.split("::program:").headOption.getOrElse("")
  if (calleeFile.nonEmpty && callerFile.nonEmpty && !callerFile.endsWith(calleeFile) && calleeFile != callerFile) {
    Some(CrossFileCall(callerFile, calleeFile, c.name, c.lineNumber.getOrElse(-1), c.code.take(80)))
  } else None
}.distinct

println(s"\n=== 진짜 cross-file 호출 후보: ${crossFile.size}건 ===")
crossFile.take(40).foreach { cf =>
  println(s"  ${cf.callerFile}:${cf.callerLine} → ${cf.calleeFile}::${cf.calleeName}()   [${cf.code}]")
}
