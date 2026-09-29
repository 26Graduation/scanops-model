/* Read-only Java G3 diagnostic export.
 *
 * Unlike dump_candidates.sc, this keeps every CALL site so a benchmark truth
 * interval can be traced without guessing from the three representative locs.
 * It is not used by the production path.
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
    case c => b.append(c)
  }
  b.toString
}

def q(s: String): String = "\"" + esc(s) + "\""

@main def exec(inDir: String, lang: String, outFile: String): Unit = {
  val proj = "java-diag"
  try importCode(inputPath = inDir, projectName = proj, language = lang)
  catch {
    case e: Throwable =>
      java.nio.file.Files.write(java.nio.file.Paths.get(outFile),
        s"""{"error":"import_failed","message":"${esc(e.toString.take(400))}"}""".getBytes)
      return
  }

  def fileOf(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): String =
    try { val v = n.file.name.l; if (v.nonEmpty) v.head else "" } catch { case _: Throwable => "" }
  def lineOf(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Int =
    try n.lineNumber.map(_.toInt).getOrElse(-1) catch { case _: Throwable => -1 }
  def safe(s: => String): String = try s catch { case _: Throwable => "" }

  val calls: List[Call] = cpg.call.l.filterNot(_.name.startsWith("<operator>"))
  val callJson = calls.map { c =>
    val m = try c.method catch { case _: Throwable => null }
    val args = try c.argument.l.sortBy(a => try a.argumentIndex catch { case _: Throwable => -1 })
               catch { case _: Throwable => Nil }
    val argsJson = args.map { a =>
      val idx = try a.argumentIndex catch { case _: Throwable => -1 }
      // Expression's generated base trait does not expose typeFullName in every
      // Joern version. Keep the field explicit-but-empty instead of inventing it.
      s"""{"index":$idx,"type":"","code":${q(safe(a.code).take(300))}}"""
    }.mkString(",")
    val visibility = if (m == null) Nil else try m.modifier.modifierType.l.map(_.toString) catch { case _: Throwable => Nil }
    val params = if (m == null) Nil else try m.parameter.nameNot("this", "self", "cls").l catch { case _: Throwable => Nil }
    val paramsJson = params.map { p =>
      val idx = try p.index catch { case _: Throwable => -1 }
      s"""{"index":$idx,"name":${q(safe(p.name))},"type":${q(safe(p.typeFullName))}}"""
    }.mkString(",")
    s"""{"file":${q(fileOf(c))},"line":${lineOf(c)},"name":${q(safe(c.name))},"method_full_name":${q(safe(c.methodFullName))},"signature":${q(safe(c.signature))},"return_type":${q(safe(c.typeFullName))},"code":${q(safe(c.code).take(500))},"arguments":[$argsJson],"enclosing_method":${q(if (m == null) "" else safe(m.name))},"enclosing_method_full_name":${q(if (m == null) "" else safe(m.fullName))},"enclosing_signature":${q(if (m == null) "" else safe(m.signature))},"enclosing_modifiers":[${visibility.map(q).mkString(",")}],"enclosing_parameters":[$paramsJson]}"""
  }

  val sb = new StringBuilder
  val methods = cpg.method.filter(_.filename.nonEmpty).l
  val methodJson = methods.map { m =>
    val start = try m.lineNumber.map(_.toInt).getOrElse(-1) catch { case _: Throwable => -1 }
    val end = try m.lineNumberEnd.map(_.toInt).getOrElse(start) catch { case _: Throwable => start }
    val cls = try m.typeDecl.name.l.headOption.getOrElse("") catch { case _: Throwable => "" }
    s"""{"file":${q(safe(m.filename))},"start":$start,"end":$end,"class":${q(cls)},"name":${q(safe(m.name))},"full_name":${q(safe(m.fullName))},"signature":${q(safe(m.signature))}}"""
  }
  sb.append(s"""{"schema":"scanops.java-cpg-diagnostics.v2","lang":${q(lang)},"n_calls":${calls.size},"calls":[""")
  sb.append(callJson.mkString(","))
  sb.append(s"""],"n_methods":${methods.size},"methods":[""")
  sb.append(methodJson.mkString(","))
  sb.append("]}")
  java.nio.file.Files.write(java.nio.file.Paths.get(outFile), sb.toString.getBytes)
  println(s"[dump_java_diagnostics] calls=${calls.size} methods=${methods.size} -> $outFile")
  try close(proj) catch { case _: Throwable => () }
  try delete(proj) catch { case _: Throwable => () }
}
