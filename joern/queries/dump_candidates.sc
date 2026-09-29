/*
 * ScanOps — GRAPH-SPEC 라운드 §5-1 "후보 API 추출"
 * ================================================
 * 레포 전체를 CPG 1개로 올린 뒤, LLM 이 source/sink/sanitizer 로 라벨링할
 * **후보 API 목록**을 덤프한다. 판정도 규칙도 여기서 하지 않는다 — 목록만 낸다.
 *
 * 덤프 내용:
 *   calls   : 호출 이름(call.name) 단위로 dedupe. methodFullName 대표값·빈도·예시 코드/파일/라인
 *   params  : 내부 메서드 파라미터. (메서드 이름, 파라미터 이름) 단위로 dedupe
 *
 * dedupe 는 **파일 수와 무관하게** 후보 수를 결정하기 위한 것이다(사양 §5: 1건씩 호출 금지).
 *
 * 호출:
 *   joern --script joern/queries/dump_candidates.sc \
 *         --param inDir=... --param lang=JSSRC --param outFile=...
 */

import io.shiftleft.codepropertygraph.generated.nodes.Call

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

@main def exec(inDir: String, lang: String, outFile: String, maxCalls: Int = 4000): Unit = {
  val proj = "candgen"
  try {
    importCode(inputPath = inDir, projectName = proj, language = lang)
  } catch {
    case e: Throwable =>
      java.nio.file.Files.write(java.nio.file.Paths.get(outFile),
        s"""{"error":"import_failed","message":"${esc(e.toString.take(400))}"}""".getBytes)
      return
  }

  def fileOf(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): String =
    try { val v = n.file.name.l; if (v.nonEmpty) v.head else "" } catch { case _: Throwable => "" }

  def lineOf(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Int =
    try { n.lineNumber.map(_.toInt).getOrElse(-1) } catch { case _: Throwable => -1 }

  // ── 호출 후보 ──────────────────────────────────────────────────────────────
  // 연산자(<operator>.*)는 API 가 아니다. 이름 기준으로 묶는다.
  val calls: List[Call] = cpg.call.l.filterNot(c => c.name.startsWith("<operator>"))

  case class CandC(name: String, fulls: Map[String, Int], n: Int,
                   codes: List[String], locs: List[String])

  val grouped = calls.groupBy(_.name).toList.map { case (nm, cs) =>
    val fulls = cs.map(_.methodFullName).groupBy(identity).map { case (k, v) => (k, v.size) }
    val codes = cs.take(60).map(_.code.replaceAll("\\s+", " ").take(180)).distinct.take(3)
    val locs  = cs.take(60).map(c => s"${fileOf(c)}:${lineOf(c)}").distinct.take(3)
    CandC(nm, fulls, cs.size, codes, locs)
  }.sortBy(-_.n).take(maxCalls)

  // ── 파라미터 후보 ──────────────────────────────────────────────────────────
  // (메서드 이름, 파라미터 이름) dedupe. 암묵 수신자(this/self)는 후보에서 뺀다.
  val params = cpg.method.filter(_.filename.nonEmpty).parameter
    .nameNot("this", "self", "cls").l
  case class CandP(mname: String, pname: String, n: Int, locs: List[String])
  val gparams = params.groupBy(p => (try p.method.name catch { case _: Throwable => "?" }, p.name))
    .toList.map { case ((mn, pn), ps) =>
      CandP(mn, pn, ps.size,
            ps.take(20).map(p => s"${try p.method.filename catch { case _: Throwable => "" }}:${lineOf(p)}").distinct.take(2))
    }.sortBy(-_.n)

  // ── 대입문 sink 후보 (PLAN.md 4단계) ─────────────────────────────────────────
  // `el.innerHTML = x` 같은 프로퍼티 대입은 함수 호출이 아니라서 위 calls 에 안 잡힌다.
  // LHS 가 <operator>.fieldAccess 인 대입만 후보로 삼는다(동적 인덱스 대입[obj[x]=..]은
  // 필드명이 없어 후보화 불가 — 범위 밖, 값을 늘리지 않는다).
  val assigns = cpg.call.name("<operator>.assignment").l.flatMap { a =>
    val lhs = a.argument.l.headOption
    lhs.flatMap { l =>
      if (l.isCall && l.asInstanceOf[Call].name == "<operator>.fieldAccess") {
        val fc = l.asInstanceOf[Call]
        val parts = fc.astChildren.l
        val fieldName = parts.lastOption.map(_.code).getOrElse("")
        if (fieldName.nonEmpty && fieldName.matches("[A-Za-z_$][A-Za-z0-9_$]*")) Some((fieldName, a)) else None
      } else None
    }
  }
  case class CandA(field: String, n: Int, codes: List[String], locs: List[String])
  val gassigns = assigns.groupBy(_._1).toList.map { case (fld, xs) =>
    val calls2 = xs.map(_._2)
    CandA(fld, calls2.size,
          calls2.take(60).map(_.code.replaceAll("\\s+", " ").take(180)).distinct.take(3),
          calls2.take(60).map(c => s"${fileOf(c)}:${lineOf(c)}").distinct.take(3))
  }.sortBy(-_.n)

  val sb = new StringBuilder
  sb.append(s"""{"lang":"${esc(lang)}","n_calls_total":${calls.size},""")
  sb.append(s""""n_call_candidates":${grouped.size},"n_param_candidates":${gparams.size},""")
  sb.append(s""""n_assign_candidates":${gassigns.size},""")
  sb.append("\"calls\":[")
  sb.append(grouped.map { c =>
    val fullsJson = c.fulls.toList.sortBy(-_._2).take(4)
      .map { case (k, v) => s"""{"full":"${esc(k)}","n":$v}""" }.mkString(",")
    s"""{"name":"${esc(c.name)}","n":${c.n},"fulls":[$fullsJson],""" +
    s""""codes":[${c.codes.map(x => "\"" + esc(x) + "\"").mkString(",")}],""" +
    s""""locs":[${c.locs.map(x => "\"" + esc(x) + "\"").mkString(",")}]}"""
  }.mkString(","))
  sb.append("],\"params\":[")
  sb.append(gparams.map { p =>
    s"""{"method":"${esc(p.mname)}","param":"${esc(p.pname)}","n":${p.n},""" +
    s""""locs":[${p.locs.map(x => "\"" + esc(x) + "\"").mkString(",")}]}"""
  }.mkString(","))
  sb.append("],\"assigns\":[")
  sb.append(gassigns.map { a =>
    s"""{"field":"${esc(a.field)}","n":${a.n},""" +
    s""""codes":[${a.codes.map(x => "\"" + esc(x) + "\"").mkString(",")}],""" +
    s""""locs":[${a.locs.map(x => "\"" + esc(x) + "\"").mkString(",")}]}"""
  }.mkString(","))
  sb.append("]}")

  java.nio.file.Files.write(java.nio.file.Paths.get(outFile), sb.toString.getBytes)
  println(s"[dump_candidates] calls=${calls.size} call_cands=${grouped.size} " +
          s"param_cands=${gparams.size} assign_cands=${gassigns.size} -> $outFile")

  try { close(proj) } catch { case _: Throwable => () }
  try { delete(proj) } catch { case _: Throwable => () }
}
