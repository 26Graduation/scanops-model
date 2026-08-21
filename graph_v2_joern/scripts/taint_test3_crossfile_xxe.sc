// 진짜 cross-file 검증: source(routes/fileUpload.ts)와 sink(lib/xml.ts)가
// 서로 다른 파일에 있는 케이스. 함수 호출 경계(caller 인자 → callee 파라미터)를
// Joern이 실제로 넘어가서 추적하는지 확인.

importCpg("C:/Users/user/Desktop/graph-experiment/juiceshop.cpg.bin")
import io.joern.dataflowengineoss.language._

// sink: lib/xml.ts 안에서 실제 파싱이 일어나는 vm.runInContext 호출
val sink = cpg.call.code(".*runInContext.*")
  .where(_.file.name(".*lib.xml.ts")).l
println(s"sink 후보 (lib/xml.ts): ${sink.size}")
sink.foreach(c => println(s"  line=${c.lineNumber.getOrElse(-1)} code=${c.code.take(90)}"))

// source: routes/fileUpload.ts 안에서 업로드된 파일 내용을 문자열로 바꾸는 지점
val source = cpg.call.code(".*file\\.buffer.*")
  .where(_.file.name(".*routes.fileUpload.ts")).l ++
  cpg.identifier.name("data")
  .where(_.file.name(".*routes.fileUpload.ts")).l
println(s"\nsource 후보 (routes/fileUpload.ts): ${source.size}")

if (sink.nonEmpty && source.nonEmpty) {
  val flows = sink.reachableByFlows(source).l
  println(s"\n=== [파일간(cross-file)] taint 경로 발견 수: ${flows.size} ===")
  if (flows.isEmpty) {
    println("!! 경로 없음 — 함수 호출 경계를 못 넘었거나 source/sink 지정이 부정확함")
  }
  flows.take(3).foreach { flow =>
    println("---- 경로 (파일명도 같이 출력) ----")
    flow.elements.foreach(e =>
      println(s"  [${e.file.name.headOption.getOrElse("?")}:${e.lineNumber.getOrElse(-1)}] ${e.code.take(70)}"))
  }
} else {
  println("sink 또는 source 후보를 못 찾음")
}
