importCpg("C:/Users/user/Desktop/graph-experiment/juiceshop.cpg.bin")
import io.joern.dataflowengineoss.language._

def compare(label: String, sinkCall: List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode],
            source: List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode]): Unit = {
  println(s"\n========== $label ==========")
  val asCallNode = sinkCall.reachableByFlows(source).l
  println(s"  콜 노드 자체로 잡은 경우(우리가 오늘 쓴 방식): ${asCallNode.size}건")

  val asArgument = sinkCall.collect { case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c }
    .flatMap(_.argument).reachableByFlows(source).l
  println(s"  .argument로 잡은 경우(조원이 말한 수정 방식):   ${asArgument.size}건")

  if (asCallNode.nonEmpty && asArgument.nonEmpty) println("  → 결론: 두 방식 다 흐름 찾음, 우리 결과 신뢰 가능")
  else if (asCallNode.isEmpty && asArgument.nonEmpty) println("  → 결론: !! 우리가 쓴 방식은 놓쳤을 것. .argument가 맞는 방식이었음")
  else if (asCallNode.nonEmpty && asArgument.isEmpty) println("  → 결론: ?? 콜 노드 방식만 잡힘, 이례적 — 추가 확인 필요")
  else println("  → 결론: 둘 다 0건")
}

// V1: login.ts SQLi
compare(
  "V1 login.ts (sequelize.query)",
  cpg.call.methodFullName(".*sequelize.*query.*").where(_.file.name(".*login.ts")).l,
  cpg.identifier.name("req").where(_.file.name(".*login.ts")).l ++
    cpg.call.code(".*req\\.body\\.email.*").where(_.file.name(".*login.ts")).l
)

// V2: dbSchemaChallenge_1.ts SQLi
compare(
  "V2 dbSchemaChallenge_1.ts (sequelize.query)",
  cpg.call.methodFullName(".*sequelize.*query.*").where(_.file.name(".*dbSchemaChallenge_1.*")).l,
  cpg.call.code(".*req\\.query\\.q.*").where(_.file.name(".*dbSchemaChallenge_1.*")).l ++
    cpg.identifier.name("criteria").where(_.file.name(".*dbSchemaChallenge_1.*")).l
)

// V3: fileUpload.ts -> xml.ts XXE
compare(
  "V3 fileUpload.ts -> xml.ts (runInContext)",
  cpg.call.code(".*runInContext.*").where(_.file.name(".*lib.xml.ts")).l,
  cpg.call.code(".*file\\.buffer.*").where(_.file.name(".*routes.fileUpload.ts")).l ++
    cpg.identifier.name("data").where(_.file.name(".*routes.fileUpload.ts")).l
)
