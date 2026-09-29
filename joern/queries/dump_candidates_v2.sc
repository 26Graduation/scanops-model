/*
 * ScanOps Java rule-generation candidates v2.
 *
 * Unlike dump_candidates.sc, calls are grouped by resolved methodFullName and
 * signature.  Bare-name/unresolved candidates remain visible but carry an
 * explicit resolution state so the product can quarantine them from enforce.
 * This script exports CPG-derived call facts only; source context is joined by
 * graph_spec_prod.py from the already supplied repository files.
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

@main def exec(inDir: String, lang: String, outFile: String, maxCalls: Int = 8000,
               projectName: String = "candgen-v2"): Unit = {
  val proj = projectName
  try importCode(inputPath = inDir, projectName = proj, language = lang)
  catch {
    case e: Throwable =>
      java.nio.file.Files.write(java.nio.file.Paths.get(outFile),
        s"""{"error":"import_failed","message":"${esc(e.toString.take(400))}"}""".getBytes)
      return
  }

  def safe(s: => String): String = try s catch { case _: Throwable => "" }
  def fileOf(c: Call): String =
    try { val xs = c.file.name.l; if (xs.nonEmpty) xs.head else "" } catch { case _: Throwable => "" }
  def lineOf(c: Call): Int =
    try c.lineNumber.map(_.toInt).getOrElse(-1) catch { case _: Throwable => -1 }
  def unresolved(full: String): Boolean =
    full.trim.isEmpty || full.startsWith("<") || full.contains("<unresolved") || full == "ANY"

  val calls = cpg.call.l.filterNot(_.name.startsWith("<operator>"))
  val grouped = calls.groupBy { c =>
    val full = safe(c.methodFullName)
    val sig = safe(c.signature)
    (full, sig, safe(c.name))
  }.toList.sortBy { case (_, cs) => -cs.size }.take(maxCalls)

  val callJson = grouped.zipWithIndex.map { case (((full, sig, name), cs), id) =>
    val resolved = !unresolved(full)
    val returnType = cs.headOption.map(c => safe(c.typeFullName)).getOrElse("")
    val sites = cs.take(6).map { c =>
      val m = try c.method catch { case _: Throwable => null }
      val mods = if (m == null) Nil else try m.modifier.modifierType.l.map(_.toString) catch { case _: Throwable => Nil }
      val anns = if (m == null) Nil else try m.annotation.name.l catch { case _: Throwable => Nil }
      val args = try c.argument.l.sortBy(a => try a.argumentIndex catch { case _: Throwable => -1 })
                 catch { case _: Throwable => Nil }
      val argsJson = args.map { a =>
        val idx = try a.argumentIndex catch { case _: Throwable => -1 }
        s"""{"index":$idx,"type":"","code":${q(safe(a.code).take(300))}}"""
      }.mkString(",")
      s"""{"file":${q(fileOf(c))},"line":${lineOf(c)},"code":${q(safe(c.code).take(500))},"arguments":[$argsJson],"enclosing_method":${q(if (m == null) "" else safe(m.name))},"enclosing_method_full_name":${q(if (m == null) "" else safe(m.fullName))},"enclosing_signature":${q(if (m == null) "" else safe(m.signature))},"visibility":[${mods.map(q).mkString(",")}],"annotations":[${anns.map(q).mkString(",")}]}"""
    }.mkString(",")
    s"""{"id":$id,"kind":"call","name":${q(name)},"method_full_name":${q(full)},"signature":${q(sig)},"return_type":${q(returnType)},"resolved":$resolved,"occurrences":${cs.size},"sites":[$sites]}"""
  }.mkString(",")

  // Public/protected project methods are potential trust boundaries.  Keep their
  // parameter endpoints exact instead of folding them into a global "all params" source.
  val internalMethods = cpg.method.filter(_.filename.nonEmpty).l.filter { m =>
    val mods = try m.modifier.modifierType.l.map(_.toString.toUpperCase).toSet catch { case _: Throwable => Set.empty[String] }
    (mods.contains("PUBLIC") || mods.contains("PROTECTED")) && !safe(m.name).startsWith("<")
  }
  val methodJson = internalMethods.zipWithIndex.map { case (m, id) =>
    val mods = try m.modifier.modifierType.l.map(_.toString) catch { case _: Throwable => Nil }
    val anns = try m.annotation.name.l catch { case _: Throwable => Nil }
    val params = try m.parameter.nameNot("this", "self", "cls").l catch { case _: Throwable => Nil }
    val paramsJson = params.map { p =>
      val idx = try p.index catch { case _: Throwable => -1 }
      s"""{"index":$idx,"name":${q(safe(p.name))},"type":${q(safe(p.typeFullName))}}"""
    }.mkString(",")
    val file = safe(m.filename)
    val line = try m.lineNumber.map(_.toInt).getOrElse(-1) catch { case _: Throwable => -1 }
    s"""{"id":$id,"kind":"internal_method","name":${q(safe(m.name))},"method_full_name":${q(safe(m.fullName))},"signature":${q(safe(m.signature))},"file":${q(file)},"line":$line,"visibility":[${mods.map(q).mkString(",")}],"annotations":[${anns.map(q).mkString(",")}],"parameters":[$paramsJson]}"""
  }.mkString(",")

  val sb = new StringBuilder
  sb.append(s"""{"schema":"scanops.rulegen-candidates.v2","lang":${q(lang)},"grouping":"methodFullName+signature","n_calls_total":${calls.size},"n_candidates":${grouped.size},"calls":[$callJson],"n_internal_methods":${internalMethods.size},"internal_methods":[$methodJson]}""")
  java.nio.file.Files.write(java.nio.file.Paths.get(outFile), sb.toString.getBytes)
  println(s"[dump_candidates_v2] calls=${calls.size} candidates=${grouped.size} -> $outFile")
  try close(proj) catch { case _: Throwable => () }
  try delete(proj) catch { case _: Throwable => () }
}
