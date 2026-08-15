/*
 * ScanOps — Joern taint 쿼리 (배치 1청크 = CPG 1개)
 * =================================================
 * 호출:
 *   joern --script joern/queries/taint.sc \
 *         --param inDir=/tmp/scanops_X/chunk0 \
 *         --param lang=JAVASRC \
 *         --param outFile=/tmp/scanops_X/chunk0.json
 *
 * inDir 안의 파일 하나 = 케이스 하나(파일명이 case_id). 한 청크를 CPG 1개로 임포트하고
 * 파일 단위로 결과를 낸다. 스크립트 종료 시 프로젝트를 close+delete 해 workspace 누수를 막는다.
 *
 * 카테고리 이름은 scanops/core/multi_graph.py 의 _CWE 11종과 1:1로 맞춘다
 * (자체 graph arm 과 나란히 비교하기 위함).
 */

import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Literal}

// ── 카테고리 정의 ───────────────────────────────────────────────────────────
// (category, cwe, sink 호출 이름 정규식). 이름 정규식은 Joern call.name 기준.
case class Rule(cat: String, cwe: String, sink: String)

val TAINT_RULES: Map[String, List[Rule]] = Map(
  "JAVASRC" -> List(
    Rule("sqli",       "CWE-89",  "(?i)(executeQuery|executeUpdate|execute|prepareStatement|createQuery|nativeQuery|rawQuery)"),
    Rule("cmdi",       "CWE-78",  "(?i)(exec|start|command)"),
    Rule("xss",        "CWE-79",  "(?i)(println|print|write|append|getWriter|setHeader|sendRedirect)"),
    Rule("pathtraver", "CWE-22",  "(?i)(<init>|newInputStream|newOutputStream|readAllBytes|createFile|mkdir|delete|renameTo)"),
    Rule("ssrf",       "CWE-918", "(?i)(openConnection|openStream|getInputStream|newBuilder|uri|url)"),
    Rule("deser",      "CWE-502", "(?i)(readObject|readUnshared|fromXML|readValue|parseObject)"),
    Rule("codei",      "CWE-94",  "(?i)(eval|compile|forName|newInstance|getMethod|invoke)")
  ),
  "PYTHONSRC" -> List(
    Rule("sqli",       "CWE-89",  "(?i)(execute|executemany|executescript|raw|extra)"),
    Rule("cmdi",       "CWE-78",  "(?i)(system|popen|call|check_output|check_call|run|Popen|spawn.*)"),
    Rule("xss",        "CWE-79",  "(?i)(HttpResponse|Markup|render_template_string|write)"),
    Rule("pathtraver", "CWE-22",  "(?i)(open|remove|unlink|rmtree|copyfile|makedirs|send_file)"),
    Rule("ssrf",       "CWE-918", "(?i)(urlopen|get|post|request|Request|urlretrieve)"),
    Rule("deser",      "CWE-502", "(?i)(loads|load|Unpickler|load_all)"),
    Rule("codei",      "CWE-94",  "(?i)(eval|exec|compile|__import__)")
  ),
  "JSSRC" -> List(
    Rule("sqli",       "CWE-89",  "(?i)(query|execute|raw|prepare)"),
    Rule("cmdi",       "CWE-78",  "(?i)(exec|execSync|spawn|spawnSync|execFile|fork)"),
    Rule("xss",        "CWE-79",  "(?i)(innerHTML|outerHTML|write|send|render|insertAdjacentHTML|dangerouslySetInnerHTML)"),
    Rule("pathtraver", "CWE-22",  "(?i)(readFile|readFileSync|writeFile|writeFileSync|createReadStream|unlink|sendFile)"),
    Rule("ssrf",       "CWE-918", "(?i)(get|post|request|fetch|axios|got)"),
    Rule("deser",      "CWE-502", "(?i)(parse|unserialize|deserialize)"),
    Rule("codei",      "CWE-94",  "(?i)(eval|Function|runInNewContext|runInThisContext)")
  )
)

// taint 흐름이 아니라 "존재 자체가 결함"인 규칙 (리터럴/호출 이름 패턴)
case class PresenceRule(cat: String, cwe: String, callRe: String, litRe: String)

val PRESENCE_RULES: List[PresenceRule] = List(
  PresenceRule("crypto",   "CWE-327", "(?i)(getInstance|createCipher|Cipher|new .*Engine)", "(?i)\"?(DES|DESede|RC2|RC4|Blowfish|AES/ECB|ECB)"),
  PresenceRule("hash",     "CWE-328", "(?i)(getInstance|createHash|new|digest|hashlib\\..*)", "(?i)\"?(MD2|MD4|MD5|SHA-?1)\""),
  PresenceRule("weakrand", "CWE-330", "(?i)(random|Random|nextInt|nextDouble|rand)", ""),
  PresenceRule("secret",   "CWE-798", "", "(?i)\"[A-Za-z0-9_\\-]{16,}\"")
)

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

@main def exec(inDir: String, lang: String, outFile: String, timeoutSec: Int = 90): Unit = {
  val proj = "batch"
  var out = new StringBuilder

  try {
    importCode(inputPath = inDir, projectName = proj, language = lang)
  } catch {
    case e: Throwable =>
      java.nio.file.Files.write(java.nio.file.Paths.get(outFile),
        s"""{"error":"import_failed","message":"${esc(e.toString.take(400))}","files":[]}""".getBytes)
      return
  }

  implicit val engineContext: EngineContext = EngineContext()

  // 임포트된 파일 목록 (Joern이 실제로 파싱한 것만 나온다)
  val parsedFiles: Set[String] =
    cpg.file.name.l.map(n => n.split("/").last).filter(_.nonEmpty).toSet

  // 파일별 메서드 존재 여부 — 메서드가 하나도 없으면 사실상 파싱 실패로 본다
  val methodFileNames: Set[String] =
    cpg.method.filter(_.filename.nonEmpty).map(_.filename.split("/").last).l.toSet

  val rules = TAINT_RULES.getOrElse(lang, Nil)

  // source = 모든 메서드 파라미터 (CleanVul 스니펫은 함수 조각 → 입력은 파라미터로 들어온다)
  //          + 프레임워크 입력 getter 호출
  val srcCalls = "(?i)(getParameter|getHeader|getQueryString|getInputStream|getCookies|input|raw_input|request|argv|getenv|environ)"

  case class Finding(file: String, cat: String, cwe: String, src: String, snk: String, line: Int, path: List[String])
  var findings = List.empty[Finding]

  // 노드 → 소속 파일명. Joern 버전에 따라 접근 경로가 다르므로 여러 전략을 순서대로 시도한다.
  def fileOf(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): String = {
    def last(s: String) = s.split("/").last
    try { val v = n.file.name.l; if (v.nonEmpty) return last(v.head) } catch { case _: Throwable => () }
    try { val v = n.method.filename; if (v.nonEmpty) return last(v) } catch { case _: Throwable => () }
    try { val v = n.method.filename.l; if (v.nonEmpty) return last(v.head) } catch { case _: Throwable => () }
    ""
  }

  for (r <- rules) {
    try {
      val sinks = cpg.call.name(r.sink)
      val sources = cpg.method.parameter
      val flows = sinks.reachableByFlows(sources).l
      for (f <- flows) {
        val elems = f.elements
        if (elems.nonEmpty) {
          val lastNode = elems.last
          val fileName = fileOf(lastNode)
          val ln = try { lastNode.lineNumber.map(_.toInt).getOrElse(-1) } catch { case _: Throwable => -1 }
          if (fileName.nonEmpty)
            findings ::= Finding(
              fileName, r.cat, r.cwe,
              elems.head.code.take(160), lastNode.code.take(160), ln,
              elems.map(_.code.take(120)).take(12)
            )
        }
      }
    } catch { case e: Throwable => System.err.println(s"[rule ${r.cat}] ${e.toString.take(200)}") }
  }

  // presence 규칙
  for (p <- PRESENCE_RULES) {
    try {
      val nodes: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode] =
        if (p.litRe.nonEmpty) cpg.literal.code(p.litRe).l
        else if (p.callRe.nonEmpty) cpg.call.name(p.callRe).l
        else Nil
      for (n <- nodes) {
        val fileName = fileOf(n)
        val ln = try { n.lineNumber.map(_.toInt).getOrElse(-1) } catch { case _: Throwable => -1 }
        if (fileName.nonEmpty)
          findings ::= Finding(fileName, p.cat, p.cwe, n.code.take(120), n.code.take(120),
                               ln, List(n.code.take(120)))
      }
    } catch { case e: Throwable => System.err.println(s"[presence ${p.cat}] ${e.toString.take(200)}") }
  }

  // ── JSON 조립 ─────────────────────────────────────────────────────────────
  val byFile = findings.groupBy(_.file)
  val allFiles = (parsedFiles ++ methodFileNames ++ byFile.keySet).filter(_.nonEmpty)

  out.append("{\"parsed\":[")
  out.append(methodFileNames.toList.sorted.map(f => "\"" + esc(f) + "\"").mkString(","))
  out.append("],\"seen\":[")
  out.append(allFiles.toList.sorted.map(f => "\"" + esc(f) + "\"").mkString(","))
  out.append("],\"findings\":[")
  out.append(findings.map { f =>
    s"""{"file":"${esc(f.file)}","category":"${esc(f.cat)}","cwe":"${esc(f.cwe)}",""" +
    s""""source":"${esc(f.src)}","sink":"${esc(f.snk)}","line":${f.line},""" +
    s""""path":[${f.path.map(p => "\"" + esc(p) + "\"").mkString(",")}]}"""
  }.mkString(","))
  out.append("]}")

  java.nio.file.Files.write(java.nio.file.Paths.get(outFile), out.toString.getBytes)

  // workspace 누수 방지 — 청크 CPG를 반드시 닫고 지운다
  try { close(proj) } catch { case _: Throwable => () }
  try { delete(proj) } catch { case _: Throwable => () }
}
