// 두 번째 검증: login.ts랑 다른 파일, 다른 코드 모양(문자열 이어붙이기 + 삼항연산자)의
// 별도 SQL Injection도 자동으로 잡히는지 확인.
// source: req.query.q (URL 쿼리파라미터, login.ts는 req.body였음 — 다른 소스)
// sink: dbSchemaChallenge_1.ts의 sequelize.query (login.ts와는 다른 파일의 다른 호출)

importCpg("C:/Users/user/Desktop/graph-experiment/juiceshop.cpg.bin")
import io.joern.dataflowengineoss.language._

val sink = cpg.call.methodFullName(".*sequelize.*query.*")
  .where(_.file.name(".*dbSchemaChallenge_1.*")).l
println(s"sink 후보: ${sink.size}")
sink.foreach(c => println(s"  line=${c.lineNumber.getOrElse(-1)} code=${c.code.take(90)}"))

val source = cpg.call.code(".*req\\.query\\.q.*")
  .where(_.file.name(".*dbSchemaChallenge_1.*")).l ++
  cpg.identifier.name("criteria")
  .where(_.file.name(".*dbSchemaChallenge_1.*")).l
println(s"\nsource 후보: ${source.size}")

if (sink.nonEmpty && source.nonEmpty) {
  val flows = sink.reachableByFlows(source).l
  println(s"\n=== taint 경로 발견 수: ${flows.size} ===")
  flows.take(2).foreach { flow =>
    println("---- 경로 ----")
    flow.elements.foreach(e => println(s"  [${e.lineNumber.getOrElse(-1)}] ${e.code.take(80)}"))
  }
} else {
  println("sink 또는 source 후보를 못 찾음")
}
