/* 2라운드 STEP 5 진단 2 — "파라미터에 뿌리내린 fieldAccess" 가설 검증.
 *
 * 진단 1 관찰: sink 에서 method.parameter 로는 flows=0 인데, 같은 메서드의
 * <operator>.fieldAccess 집합에서는 flows>0 이 나온다.
 * 가설: JSSRC 는 METHOD_PARAMETER_IN 과 `param.a.b` fieldAccess 사이에
 *       데이터 의존 엣지를 만들지 않는다 → 파라미터를 source 로 쓰면 아무것도 안 잡힌다.
 * 검증: fieldAccess 를 **뿌리 식별자가 그 메서드의 파라미터인 것만** 골라 source 로 썼을 때
 *       flow 가 생기는지 본다. 파일명·변수명 하드코딩 없이 구조만 본다.
 */
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(inDir: String, lang: String, outFile: String, sinkRe: String): Unit = {
  importCode(inputPath = inDir, projectName = "diagsrc", language = lang)
  implicit val ec: EngineContext = EngineContext()
  val sb = new StringBuilder

  // formatString 이 기본 semantics 에 있는가 (있으면 전파가 한정된다)
  val ops = io.joern.dataflowengineoss.DefaultSemantics.operatorFlows.map(_.methodFullName).toSet
  sb.append(s"formatString in DefaultSemantics? ${ops.contains("<operator>.formatString")}\n")
  sb.append(s"addition in DefaultSemantics?     ${ops.contains("<operator>.addition")}\n")
  sb.append(s"assignment in DefaultSemantics?   ${ops.contains("<operator>.assignment")}\n")
  sb.append(s"fieldAccess in DefaultSemantics?  ${ops.contains("<operator>.fieldAccess")}\n\n")

  /* 뿌리 식별자 이름을 뽑는다: fieldAccess 의 code 맨 앞 식별자.
   * 예) "req.body.email" -> "req". 구조적 규칙이고 특정 이름을 가정하지 않는다. */
  def rootName(code: String): String = {
    val t = code.trim
    val m = "^([A-Za-z_$][A-Za-z0-9_$]*)".r.findFirstMatchIn(t)
    if (m.isDefined) m.get.group(1) else ""
  }

  val sinks = cpg.call.methodFullName(sinkRe).l
  sb.append(s"sink 수: ${sinks.size}\n")
  for (s <- sinks) {
    val f = try s.file.name.l.headOption.getOrElse("?") catch { case _: Throwable => "?" }
    val m = s.method
    val pnames = try m.parameter.nameNot("this").name.l.toSet catch { case _: Throwable => Set.empty[String] }
    val allFa = try cpg.call.name("<operator>.fieldAccess").filter(_.method.id == m.id).l
                catch { case _: Throwable => Nil }
    val rooted = allFa.filter(c => pnames.contains(rootName(c.code)))
    def flowsFrom(xs: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode]): Int =
      try List(s).iterator.reachableByFlows(xs.iterator).l.size catch { case _: Throwable => -1 }
    val params = try m.parameter.nameNot("this").l catch { case _: Throwable => Nil }
    sb.append(s"\n* ${f}:${s.lineNumber.getOrElse(-1)}  method=${m.name} params=${pnames.mkString(",")}\n")
    sb.append(s"    flows from METHOD_PARAMETER_IN : ${flowsFrom(params)}\n")
    sb.append(s"    fieldAccess in method          : ${allFa.size}\n")
    sb.append(s"    fieldAccess rooted at a param  : ${rooted.size}  ${rooted.map(_.code.take(28)).distinct.take(6).mkString(" | ")}\n")
    sb.append(s"    flows from param-rooted fA     : ${flowsFrom(rooted)}\n")
    // 파라미터 이름과 같은 IDENTIFIER 노드에서는?
    val idents = try cpg.identifier.filter(i => i.method.id == m.id && pnames.contains(i.name)).l
                 catch { case _: Throwable => Nil }
    sb.append(s"    IDENTIFIER == param name       : ${idents.size}\n")
    sb.append(s"    flows from those IDENTIFIERs   : ${flowsFrom(idents)}\n")
  }
  java.nio.file.Files.write(java.nio.file.Paths.get(outFile), sb.toString.getBytes)
  println(sb.toString)
}
