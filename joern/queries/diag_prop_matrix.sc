/* 2라운드 STEP 5 — 전파 유형별 검증 행렬.
 * 합성 코드에서 source 전략 2가지(파라미터 / 파라미터뿌리 fieldAccess)를 놓고
 * 5가지 전파 패턴이 각각 sink 에 도달하는지 센다. 레포 코드와 무관하다. */
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(inDir: String, lang: String, outFile: String, sinkRe: String): Unit = {
  importCode(inputPath = inDir, projectName = "propmatrix", language = lang)
  implicit val ec: EngineContext = EngineContext()
  val sb = new StringBuilder
  def rootName(code: String): String = {
    val m = "^([A-Za-z_$][A-Za-z0-9_$]*)".r.findFirstMatchIn(code.trim)
    if (m.isDefined) m.get.group(1) else ""
  }
  // 전역: 모든 메서드의 파라미터 / 파라미터뿌리 fieldAccess
  val allParams = cpg.method.parameter.nameNot("this", "self", "cls").l
  val allFa = cpg.call.name("<operator>.fieldAccess").l.filter { c =>
    val pn = try c.method.parameter.nameNot("this", "self", "cls").name.l.toSet
             catch { case _: Throwable => Set.empty[String] }
    pn.contains(rootName(c.code))
  }
  sb.append(s"params=${allParams.size} paramRootedFieldAccess=${allFa.size}\n\n")
  val sinks = cpg.call.name(sinkRe).l
  sb.append(s"sink 수: ${sinks.size}\n")
  sb.append(f"${"line"}%6s ${"패턴"}%-34s ${"params"}%8s ${"paramFA"}%8s ${"둘다"}%8s\n")
  for (s <- sinks.sortBy(_.lineNumber.getOrElse(0))) {
    def n(xs: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode]): Int =
      try List(s).iterator.reachableByFlows(xs.iterator).l.size catch { case _: Throwable => -1 }
    val both = (allParams ++ allFa)
    sb.append(f"${s.lineNumber.getOrElse(-1)}%6d ${s.code.replaceAll("\\s+"," ").take(34)}%-34s " +
              f"${n(allParams)}%8d ${n(allFa)}%8d ${n(both)}%8d\n")
  }
  java.nio.file.Files.write(java.nio.file.Paths.get(outFile), sb.toString.getBytes)
  println(sb.toString)
}
