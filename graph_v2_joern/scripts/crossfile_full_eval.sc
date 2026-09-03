// 사전등록: find_crossfile_candidates.sc가 찾은 131건 cross-file 호출 "전체"에 대해
// 자동으로 (source→callee내부sink) taint 확인을 돌린다. 하나 손으로 고르지 않는다.
// 자명 기준선(131건 전부 vuln이라 찍었을 때 정밀도) vs 우리 판정(taint 확인된 것만 vuln)을 비교.

importCpg("C:/Users/user/Desktop/graph-experiment/juiceshop.cpg.bin")
import io.joern.dataflowengineoss.language._

// scanops/core/multi_graph.py의 11개 카테고리 sink 패턴을 그대로 가져옴 (Node/JS 기준)
val SINK_PATTERNS = List(
  "\\.exec\\(", "child_process", "execSync",                          // cmdi
  "\\.query\\(", "sequelize", "\\$where",                              // sqli
  "innerHTML", "dangerouslySetInnerHTML", "\\.write\\(", "res\\.send", // xss
  "readFile", "writeFile", "createReadStream", "sendFile", "unlink",   // pathtraver
  "\\bfetch\\(", "axios", "\\.get\\(|\\.post\\(",                      // ssrf
  "\\.parse\\(", "unserialize", "runInContext",                        // deser/codei
  "\\beval\\(", "new Function"                                        // codei
)
val SOURCE_PATTERNS = List("req\\.", "request\\.", "\\.body\\b", "\\.query\\b", "\\.params\\b")

case class CrossFileCall(callerFile: String, calleeFile: String, calleeName: String, callerLine: Int)

val internalCalls = cpg.call.filter(_.methodFullName.contains("::program:")).l
val crossFile = internalCalls.flatMap { c =>
  val callerFile = c.file.name.headOption.getOrElse("")
  val calleeFile = c.methodFullName.split("::program:").headOption.getOrElse("")
  if (calleeFile.nonEmpty && callerFile.nonEmpty && !callerFile.endsWith(calleeFile) && calleeFile != callerFile)
    Some(CrossFileCall(callerFile, calleeFile, c.name, c.lineNumber.getOrElse(-1)))
  else None
}.distinct

println(s"자명 기준선(전수): ${crossFile.size}건 (전부 'vuln'이라 찍었을 때)")

// 각 cross-file 호출에 대해: callee 함수 안에 sink 패턴이 있고, caller 쪽에 source 패턴이 있는지 확인
var confirmedCount = 0
val confirmed = scala.collection.mutable.ListBuffer[String]()

// 파일명 정확히 일치하는 걸로 미리 그룹핑 (정규식 이스케이프 문제 회피)
val callsByFile = cpg.call.l.groupBy(_.file.name.headOption.getOrElse(""))

crossFile.foreach { cf =>
  val calleeCalls = callsByFile.getOrElse(cf.calleeFile, Nil)
  val calleeSinkExists = calleeCalls.exists(c => SINK_PATTERNS.exists(p => c.code.matches(s"(?s).*$p.*")))

  if (calleeSinkExists) {
    val callerCalls = callsByFile.getOrElse(cf.callerFile, Nil)
    val callerSourceExists = callerCalls.exists(c => SOURCE_PATTERNS.exists(p => c.code.matches(s"(?s).*$p.*")))
    if (callerSourceExists) {
      confirmedCount += 1
      confirmed += s"${cf.callerFile}:${cf.callerLine} -> ${cf.calleeFile}::${cf.calleeName}()"
    }
  }
}

println(s"\n우리 판정(source있음 + callee에 sink있음) 통과: ${confirmedCount}건")
println(s"자명 기준선 대비 걸러낸 비율: ${math.round((1.0 - confirmedCount.toDouble/crossFile.size)*10000)/100.0}%")
println(s"\n=== 통과한 목록 (사람이 최종 확인해야 할 후보) ===")
confirmed.foreach(println)
