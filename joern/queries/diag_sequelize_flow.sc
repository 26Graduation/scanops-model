@main def exec(inDir: String, lang: String, outFile: String): Unit = {
  importCode(inputPath = inDir, projectName = "diag", language = lang)
  implicit val ec: io.joern.dataflowengineoss.queryengine.EngineContext =
    io.joern.dataflowengineoss.queryengine.EngineContext()
  import io.joern.dataflowengineoss.language._
  val sb = new StringBuilder
  val sinks = cpg.call.methodFullName("^.*sequelize.*:query$").l
  sb.append(s"sinks matched: ${sinks.size}\n")
  for (s <- sinks) {
    val f = try s.file.name.l.headOption.getOrElse("?") catch { case _: Throwable => "?" }
    sb.append(s"  ${f}:${s.lineNumber.getOrElse(-1)}  full=${s.methodFullName}\n")
    val ps = cpg.method.parameter.nameNot("this","self","cls").l
    val fl = try List(s).iterator.reachableByFlows(ps).l.size catch { case e: Throwable => -1 }
    sb.append(s"    flows from params: ${fl}\n")
    val encl = try s.method.name catch { case _: Throwable => "?" }
    sb.append(s"    enclosing method: ${encl}\n")
    val mp = try s.method.parameter.name.l.mkString(",") catch { case _: Throwable => "?" }
    sb.append(s"    enclosing method params: ${mp}\n")
  }
  java.nio.file.Files.write(java.nio.file.Paths.get(outFile), sb.toString.getBytes)
  println(sb.toString)
}
