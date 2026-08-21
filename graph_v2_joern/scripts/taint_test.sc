importCpg("C:/Users/user/Desktop/graph-experiment/juiceshop.cpg.bin")
import io.joern.dataflowengineoss.language._

println("=== 1. login.ts:34 부근의 sequelize.query 호출 노드 확인 ===")
val sinkCandidates = cpg.call.where(_.file.name(".*login.ts")).l
sinkCandidates.filter(_.code.contains("query")).foreach { c =>
  println(s"line=${c.lineNumber.getOrElse(-1)} name=${c.name} methodFullName=${c.methodFullName} code=${c.code.take(80)}")
}

println("\n=== 2. 우리 문서가 지적한 정규식(?i)(query|execute|raw|prepare) 이 call.name에 매칭되는지 ===")
val regexSinks = cpg.call.name("(?i).*(query|execute|raw|prepare).*").where(_.file.name(".*login.ts")).l
println(s"call.name 기준 매칭 수: ${regexSinks.size}")
regexSinks.foreach(c => println(s"  line=${c.lineNumber.getOrElse(-1)} name=${c.name} code=${c.code.take(60)}"))

println("\n=== 3. source 후보: req.body 관련 접근 ===")
val sources = cpg.call.where(_.file.name(".*login.ts")).code(".*req\\.body.*").l
println(s"소스 후보 수: ${sources.size}")
sources.take(5).foreach(c => println(s"  line=${c.lineNumber.getOrElse(-1)} code=${c.code.take(80)}"))

println("\n=== 4. 실제 sink 노드 지정 (methodFullName 기준) 후 taint 흐름 추적 ===")
val realSink = cpg.call.methodFullName(".*sequelize.*query.*|.*query.*").where(_.file.name(".*login.ts")).l
println(s"실sink 노드 수: ${realSink.size}")

val realSource = cpg.identifier.name("req").where(_.file.name(".*login.ts")).l ++
                  cpg.call.code(".*req\\.body\\.email.*").where(_.file.name(".*login.ts")).l
println(s"실source 노드 수: ${realSource.size}")

if (realSink.nonEmpty && realSource.nonEmpty) {
  val flows = realSink.reachableByFlows(realSource).l
  println(s"\n=== 5. taint 경로 발견 수: ${flows.size} ===")
  flows.take(3).foreach { flow =>
    println("---- 경로 ----")
    flow.elements.foreach(e => println(s"  [${e.lineNumber.getOrElse(-1)}] ${e.code.take(70)}"))
  }
} else {
  println("sink 또는 source 후보를 못 찾음")
}
