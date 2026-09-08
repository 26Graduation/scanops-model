/* ScanOps 3라운드 — 위치 프로브 (관찰 전용).
 *
 * (파일, 라인) 목록을 받아 그 지점의 CPG 구조를 덤프한다. 판정도 룰도 없다.
 * 목록은 **명령행 파일**로 주입한다 — 스크립트 본문에 벤치 경로를 넣지 않는다.
 *
 * locFile 형식: "<상대경로>\t<라인>" 한 줄씩
 *
 * 덤프: 그 라인의 CALL 노드(name/methodFullName/code), 감싸는 메서드와 파라미터,
 *       그 메서드의 파라미터뿌리 fieldAccess, 그 라인 CALL 로의 도달 flow 수,
 *       그 라인의 LITERAL/IDENTIFIER 수 (호출이 아예 없는 자리인지 구분용)
 */
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

def esc(s: String): String = {
  val b = new StringBuilder
  s.foreach {
    case '"'  => b.append("\\\"");  case '\\' => b.append("\\\\")
    case '\n' => b.append("\\n");   case '\r' => b.append("\\r")
    case '\t' => b.append("\\t")
    case c if c < ' ' => b.append("\\u%04x".format(c.toInt))
    case c    => b.append(c)
  }
  b.toString
}

@main def exec(inDir: String, lang: String, outFile: String, locFile: String): Unit = {
  importCode(inputPath = inDir, projectName = "probe", language = lang)
  implicit val ec: EngineContext = EngineContext()

  val base = { val b = inDir.stripSuffix("/"); b + "/" }
  def rel(s: String): String = if (s.startsWith(base)) s.substring(base.length) else s
  def rootIdent(code: String): String = {
    val m = "^([A-Za-z_$][A-Za-z0-9_$]*)".r.findFirstMatchIn(code.trim)
    if (m.isDefined) m.get.group(1) else ""
  }

  val locs = {
    val src = scala.io.Source.fromFile(locFile, "UTF-8")
    try src.getLines().toList.flatMap { ln =>
      val p = ln.split("\t")
      if (p.length >= 2) try Some((p(0), p(1).trim.toInt)) catch { case _: Throwable => None }
      else None
    } finally src.close()
  }

  // 전역 source 집합 (R2 srcMode=r2 와 동일 규칙)
  val allParams = cpg.method.parameter.nameNot("this", "self", "cls").l
  val faSources = cpg.call.name("<operator>.fieldAccess").l.filter { c =>
    val pn = try c.method.parameter.nameNot("this", "self", "cls").name.l.toSet
             catch { case _: Throwable => Set.empty[String] }
    val r = rootIdent(c.code); r.nonEmpty && pn.contains(r)
  }

  val sb = new StringBuilder
  sb.append("[")
  var first = true
  for ((f, line) <- locs) {
    val callsAt = cpg.call.l.filter { c =>
      (try rel(c.file.name.l.headOption.getOrElse("")) catch { case _: Throwable => "" }) == f &&
      c.lineNumber.map(_.toInt).getOrElse(-1) == line
    }
    val apiCalls = callsAt.filterNot(_.name.startsWith("<operator>"))
    val litsAt = cpg.literal.l.count { n =>
      (try rel(n.file.name.l.headOption.getOrElse("")) catch { case _: Throwable => "" }) == f &&
      n.lineNumber.map(_.toInt).getOrElse(-1) == line
    }
    val m = apiCalls.headOption.orElse(callsAt.headOption).map(_.method)
    val pn = m.map(x => try x.parameter.nameNot("this","self","cls").name.l
                        catch { case _: Throwable => Nil }).getOrElse(Nil)
    val faIn = m.map(x => faSources.filter(_.method.id == x.id)).getOrElse(Nil)
    val flows = if (apiCalls.isEmpty) 0 else
      (try apiCalls.iterator.reachableByFlows((allParams ++ faSources).iterator).l.size
       catch { case _: Throwable => -1 })
    val flowsFaOnly = if (apiCalls.isEmpty) 0 else
      (try apiCalls.iterator.reachableByFlows(faSources.iterator).l.size
       catch { case _: Throwable => -1 })

    if (!first) sb.append(",")
    first = false
    sb.append(s"""{"file":"${esc(f)}","line":$line,""")
    sb.append(s""""n_calls_at_line":${callsAt.size},"n_api_calls_at_line":${apiCalls.size},""")
    sb.append(s""""n_literals_at_line":$litsAt,""")
    sb.append(s""""enclosing_method":"${esc(m.map(_.name).getOrElse(""))}",""")
    sb.append(s""""enclosing_params":[${pn.map(x => "\"" + esc(x) + "\"").mkString(",")}],""")
    sb.append(s""""n_param_rooted_fieldaccess_in_method":${faIn.size},""")
    sb.append(s""""param_rooted_fieldaccess_samples":[${faIn.map(_.code.replaceAll("\\s+"," ").take(50)).distinct.take(5).map(x => "\"" + esc(x) + "\"").mkString(",")}],""")
    sb.append(s""""flows_from_all_sources":$flows,"flows_from_fieldaccess_only":$flowsFaOnly,""")
    sb.append(s""""api_calls":[${apiCalls.take(6).map(c =>
      s"""{"name":"${esc(c.name)}","full":"${esc(c.methodFullName)}","code":"${esc(c.code.replaceAll("\\s+"," ").take(120))}"}""").mkString(",")}],""")
    sb.append(s""""operator_calls":[${callsAt.filter(_.name.startsWith("<operator>")).take(6).map(c =>
      s"""{"name":"${esc(c.name)}","code":"${esc(c.code.replaceAll("\\s+"," ").take(100))}"}""").mkString(",")}]}""")
  }
  sb.append("]")
  java.nio.file.Files.write(java.nio.file.Paths.get(outFile), sb.toString.getBytes)
  println(s"[probe] ${locs.size} locations -> $outFile")
}
