/*
 * ScanOps — 2라운드 STEP 5 진단: JSSRC 가 템플릿 리터럴/문자열 연결을 어떤 노드·엣지로 만드는가
 * ============================================================================
 * **고치기 전에 본다.** 추측으로 전파 규칙을 쓰지 않기 위한 관찰 전용 스크립트다.
 * 특정 파일명·라인을 인자로 받지 않는다. 레포 전체에서 구조를 훑는다.
 *
 * 보는 것:
 *  A) 템플릿 리터럴이 어떤 call/operator 로 표현되는가 (이름·빈도·예시)
 *  B) 그 노드의 인자(argument) 들이 무엇인가 — 보간식이 인자로 붙는가
 *  C) 그 노드에 대한 기본 semantics 가 있는가 (없으면 Joern 기본 = 전부 전파)
 *  D) sqli sink 로 들어가는 인자에서 역방향으로 ddgIn 을 따라가면 어디서 끊기는가
 *  E) 파라미터 → sink 도달이 실패하는 대표 사례의 AST/DDG 이웃
 */

import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

def esc(s: String): String = {
  val b = new StringBuilder
  s.foreach {
    case '"'  => b.append("\\\"")
    case '\\' => b.append("\\\\")
    case '\n' => b.append("\\n")
    case '\r' => b.append("\\r")
    case '\t' => b.append("\\t")
    case c if c < ' ' => b.append("\\u%04x".format(c.toInt))
    case c    => b.append(c)
  }
  b.toString
}

@main def exec(inDir: String, lang: String, outFile: String, sinkRe: String): Unit = {
  importCode(inputPath = inDir, projectName = "diagprop", language = lang)
  implicit val ec: EngineContext = EngineContext()

  val sb = new StringBuilder
  def sec(t: String): Unit = sb.append(s"\n===== $t =====\n")

  // ── A) 연산자/호출 이름 분포: 템플릿·연결 관련 후보 ────────────────────────
  sec("A. operator/call name 분포 (템플릿·문자열 연결 후보)")
  val interesting = List("template", "Template", "concat", "addition", "plus", "format", "join")
  val names = cpg.call.name.l.groupBy(identity).map { case (k, v) => (k, v.size) }.toList
    .sortBy(-_._2)
  val hits = names.filter { case (n, _) => interesting.exists(i => n.toLowerCase.contains(i.toLowerCase)) }
  hits.foreach { case (n, c) => sb.append(f"  $c%6d  $n\n") }
  sb.append("  -- 상위 연산자 20개 --\n")
  names.filter(_._1.startsWith("<operator>")).take(20).foreach { case (n, c) =>
    sb.append(f"  $c%6d  $n\n") }

  // ── B) 템플릿 리터럴 노드의 인자 구조 ──────────────────────────────────────
  sec("B. 템플릿 리터럴 노드의 인자 구조 (예시 5개)")
  val tmplNames = names.map(_._1).filter(n =>
    n.toLowerCase.contains("template") || n == "<operator>.formatString")
  sb.append(s"  템플릿 후보 이름: ${tmplNames.mkString(", ")}\n")
  val tmplCalls = if (tmplNames.isEmpty) Nil else cpg.call.nameExact(tmplNames: _*).l
  sb.append(s"  템플릿 노드 수: ${tmplCalls.size}\n")
  tmplCalls.take(5).foreach { c =>
    val f = try c.file.name.l.headOption.getOrElse("?") catch { case _: Throwable => "?" }
    sb.append(s"  - ${f}:${c.lineNumber.getOrElse(-1)} name=${c.name} full=${c.methodFullName}\n")
    sb.append(s"    code=${c.code.replaceAll("\\s+", " ").take(140)}\n")
    val args = try c.argument.l catch { case _: Throwable => Nil }
    sb.append(s"    args(${args.size}): " +
      args.take(6).map(a => s"[${a.argumentIndex}]${a.label}:${a.code.replaceAll("\\s+"," ").take(50)}").mkString(" ") + "\n")
  }

  // ── C) sink 인자에서 역방향 DDG ────────────────────────────────────────────
  sec("C. sink 인자의 역방향 DDG (sinkRe 로 지정한 sink)")
  val sinks = cpg.call.methodFullName(sinkRe).l
  sb.append(s"  sink 매칭 수: ${sinks.size}\n")
  for (s <- sinks.take(4)) {
    val f = try s.file.name.l.headOption.getOrElse("?") catch { case _: Throwable => "?" }
    sb.append(s"\n  * ${f}:${s.lineNumber.getOrElse(-1)}  ${s.code.replaceAll("\\s+"," ").take(120)}\n")
    val args = try s.argument.l catch { case _: Throwable => Nil }
    for (a <- args.take(3)) {
      sb.append(s"    arg[${a.argumentIndex}] label=${a.label} code=${a.code.replaceAll("\\s+"," ").take(90)}\n")
      // 이 인자가 어떤 AST 자식들을 갖는가 (보간식이 자식으로 붙는지)
      val kids = try a.astChildren.l catch { case _: Throwable => Nil }
      sb.append(s"      astChildren(${kids.size}): " +
        kids.take(6).map(k => s"${k.label}:${k.code.replaceAll("\\s+"," ").take(40)}").mkString(" | ") + "\n")
      // 역방향 데이터 의존
      val din = try a.ddgIn.l catch { case _: Throwable => Nil }
      sb.append(s"      ddgIn(${din.size}): " +
        din.take(6).map(k => s"${k.label}:${k.code.replaceAll("\\s+"," ").take(40)}").mkString(" | ") + "\n")
    }
    // 감싸는 메서드의 파라미터에서 이 sink 로 flow 가 있는가
    val mps = try s.method.parameter.nameNot("this").l catch { case _: Throwable => Nil }
    val fl = try List(s).iterator.reachableByFlows(mps.iterator).l.size catch { case _: Throwable => -1 }
    sb.append(s"    enclosing method=${s.method.name} params=${mps.map(_.name).mkString(",")} flows=${fl}\n")
    // 파라미터의 필드 접근(req.body 등)에서 flow 가 있는가
    val fieldAcc = try cpg.call.name("<operator>.fieldAccess")
      .filter(c => c.method.id == s.method.id).l catch { case _: Throwable => Nil }
    val fl2 = try List(s).iterator.reachableByFlows(fieldAcc.iterator).l.size catch { case _: Throwable => -1 }
    sb.append(s"    fieldAccess in same method=${fieldAcc.size} flowsFromFieldAccess=${fl2}\n")
    fieldAcc.take(4).foreach { fa =>
      sb.append(s"      fa: ${fa.code.replaceAll("\\s+"," ").take(70)}\n") }
  }

  // ── D) 기본 semantics 유무 ─────────────────────────────────────────────────
  sec("D. 참고: 기본 semantics 에 등록된 연산자 수")
  val opFlows = io.joern.dataflowengineoss.DefaultSemantics.operatorFlows
  sb.append(s"  DefaultSemantics.operatorFlows 개수: ${opFlows.size}\n")
  opFlows.take(30).foreach { fs => sb.append(s"    ${fs.methodFullName}\n") }

  java.nio.file.Files.write(java.nio.file.Paths.get(outFile), sb.toString.getBytes)
  println(sb.toString)
}
