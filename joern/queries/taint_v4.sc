/*
 * ScanOps — Joern taint 쿼리 **규칙 v3 (sanitizer-aware)**
 * =================================================
 * v2 대비 변경점 (오늘 세션):
 *  1) flow 의 각 노드를 sanitizer 정규식과 대조해, 걸리면 그 flow 를 제외한다.
 *     한 (파일,카테고리)의 flow 가 전부 제외되면 findings 에 sanitized=true 로 남겨
 *     핸들러가 verdict=safe_sanitized 로 낮출 수 있게 한다.
 *  2) path 를 코드 문자열이 아니라 {line, code, role} 객체 배열로 낸다.
 *     role = source | intermediate | sink. LLM Critic 의 입력 규격이다.
 *  3) sanitizer 표는 코드가 아니라 sanFile(=joern/sanitizers.json 에서 파생된 텍스트)로 주입한다.
 *
 * 호출:
 *   joern --script joern/queries/taint_v3.sc \
 *         --param inDir=/tmp/scanops_X/chunk0 \
 *         --param lang=JAVASRC \
 *         --param outFile=/tmp/scanops_X/chunk0.json \
 *         --param sanFile=/tmp/scanops_X/_san.txt
 *
 * sanFile 형식(파이썬이 sanitizers.json 에서 생성):
 *   한 줄에 "<category>\t<regex>" — category "_any" 는 모든 카테고리에 적용.
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
// field = "name"(호출 이름) | "full"(methodFullName). 생성자·패키지 구분에 full 이 필요하다.
case class Rule(cat: String, cwe: String, sink: String, field: String = "name")

val TAINT_RULES: Map[String, List[Rule]] = Map(
  "JAVASRC" -> List(
    Rule("sqli",       "CWE-89",  "(?i)(executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery)"),
    Rule("cmdi",       "CWE-78",  "(?i).*(Runtime\\.exec|ProcessBuilder).*", "full"),
    // v1 결함: println/print/write/append 는 로깅까지 전부 잡았다 → 응답 출력 경로만 남긴다
    Rule("xss",        "CWE-79",  "(?i)(getWriter|sendRedirect|setHeader|addHeader)"),
    // v1 결함: <init> 가 모든 생성자를 잡았다 → File/Path/Files 패키지로 한정
    Rule("pathtraver", "CWE-22",  "(?i).*(java\\.io\\.File|java\\.nio\\.file\\.(Files|Paths))\\..*", "full"),
    // v1 결함: uri|url|newBuilder|getInputStream 는 너무 넓다
    Rule("ssrf",       "CWE-918", "(?i)(openConnection|openStream)"),
    Rule("deser",      "CWE-502", "(?i)(readObject|readUnshared|fromXML|readValue)"),
    Rule("codei",      "CWE-94",  "(?i)(eval|forName|getMethod|invoke)")
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

// v2: 존재 규칙은 대부분 오탐원이었다(§4-1). secret/weakrand 는 조건을 붙이고,
// 근거가 리터럴 하나뿐인 규칙은 taint 판정과 동급으로 쓰지 않는다.
val PRESENCE_RULES: List[PresenceRule] = List(
  PresenceRule("crypto",   "CWE-327", "", "(?i)\"(DES|DESede|RC2|RC4|Blowfish|AES/ECB|.*ECB.*)\""),
  PresenceRule("hash",     "CWE-328", "", "(?i)\"(MD2|MD4|MD5|SHA-?1)\""),
  // v1 결함: 이름에 random 이 들어간 모든 호출(SecureRandom 포함)을 잡았다
  PresenceRule("weakrand", "CWE-330", "(?i).*(java\\.util\\.Random|Math\\.random)\\..*", "")
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

@main def exec(inDir: String, lang: String, outFile: String, sanFile: String = "",
               timeoutSec: Int = 90): Unit = {
  val proj = "batch"
  var out = new StringBuilder

  // ── sanitizer 표 로드 ─────────────────────────────────────────────────────
  // "<category>\t<regex>" 줄들. category "_any" 는 전 카테고리 공통.
  /* v4: sanFile 형식이 3열로 바뀌었다 — "<블록카테고리>\t<applies_to,콤마구분>\t<regex>"
   * 매칭 조건 = (finding 카테고리가 applies_to 에 포함) OR (applies_to 에 "*").
   * 블록 카테고리는 더 이상 매칭에 쓰지 않는다(§8 D-1). */
  case class SanPat(applies: Set[String], p: java.util.regex.Pattern)

  val sanAll: List[SanPat] = {
    if (sanFile.isEmpty) Nil
    else try {
      val src = scala.io.Source.fromFile(sanFile, "UTF-8")
      val lines = try src.getLines().toList finally src.close()
      lines.flatMap { ln =>
        val parts = ln.split("\t", 3)
        if (parts.length < 3) None
        else {
          val applies = parts(1).split(",").map(_.trim).filter(_.nonEmpty).toSet
          val re = parts(2).trim
          if (re.isEmpty || applies.isEmpty) None
          else try Some(SanPat(applies, java.util.regex.Pattern.compile(re)))
               catch { case _: Throwable => None }
        }
      }
    } catch { case _: Throwable => Nil }
  }

  def sanPatternsFor(cat: String): List[java.util.regex.Pattern] =
    sanAll.filter(sp => sp.applies.contains("*") || sp.applies.contains(cat)).map(_.p)

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

  // path 원소: 라인번호 + 코드 + 역할(source/intermediate/sink)
  case class Step(line: Int, code: String, role: String)
  // sanitizer 적중: 어느 노드(라인/코드/역할)가 어느 패턴에 걸렸는가
  case class SanHit(line: Int, code: String, role: String, pattern: String)
  case class Finding(file: String, cat: String, cwe: String, src: String, snk: String, line: Int,
                     path: List[Step], sanitized: Boolean, sanHits: List[SanHit])
  var findings = List.empty[Finding]

  // 노드 → 소속 파일명. Joern 버전에 따라 접근 경로가 다르므로 여러 전략을 순서대로 시도한다.
  def fileOf(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): String = {
    def last(s: String) = s.split("/").last
    // AstNode 에는 .method 가 없다(컴파일 실측). .file 트래버설만 쓴다.
    try { val v = n.file.name.l; if (v.nonEmpty) return last(v.head) } catch { case _: Throwable => () }
    ""
  }

  def lineOf(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Int =
    try { n.lineNumber.map(_.toInt).getOrElse(-1) } catch { case _: Throwable => -1 }

  /* flow 의 원소는 **추적되는 식**(`ps`, `name`)이지 문장이 아니다(스모크 실측).
   * 그래서 노드 코드만 보면 `ps.setString(1, name)` 같은 sanitizer 호출을 영영 못 본다.
   * → 노드 자신 + 상위 AST 3단계의 code 를 함께 검사한다. 흐름에 국한되므로
   *   "파일 어딘가에 setString 이 있으면 안전" 같은 과광의 매칭이 되지 않는다. */
  def enclosingCodes(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): List[String] = {
    var acc = List(n.code.take(300))
    var cur: io.shiftleft.codepropertygraph.generated.nodes.AstNode = n
    var i = 0
    while (i < 3) {
      val p = try cur.astParent catch { case _: Throwable => null }
      if (p == null) { i = 3 }
      else {
        val c = try p.code.take(300) catch { case _: Throwable => "" }
        if (c.nonEmpty) acc = acc :+ c
        cur = p
        i += 1
      }
    }
    acc.distinct
  }

  for (r <- rules) {
    try {
      val sinks = if (r.field == "full") cpg.call.methodFullName(r.sink) else cpg.call.name(r.sink)
      /* v4 결함 수정 ①: `self`(Python) / `this`(Java·JS) 는 taint source 가 아니다.
       * `cpg.method.parameter` 는 암묵 수신자까지 포함해서, 어제 Python 오탐 5건 중 3건이
       * source=`self` 였다(어제 §4-1). 수신자는 사용자 입력이 아니다.
       *
       * 주의: `self.request.args` 처럼 **self 를 통해 들어오는 진짜 source** 는 살려야 한다.
       * 그건 파라미터 노드가 아니라 필드 접근/호출로 잡히므로, 아래 srcCalls 경로가 담당한다.
       * 여기서 빼는 것은 "파라미터 `self` 자체"뿐이다. */
      val paramSources = cpg.method.parameter.nameNot("self", "this", "cls").l
      /* v4 결함 수정 ①-b: v3 에서 `srcCalls` 는 **정의만 되고 쓰이지 않았다**(실측).
       * 그래서 `self.request.args` 같은 프레임워크 입력이 source 로 잡히지 않았다.
       * 파라미터에서 self/this 를 빼는 대신, 진짜 입력 getter 를 source 에 더한다. */
      val callSources = cpg.call.name(srcCalls).l
      val sources = paramSources ++ callSources
      val flows = sinks.reachableByFlows(sources).l
      val pats = sanPatternsFor(r.cat)
      for (f <- flows) {
        val elems = f.elements
        if (elems.nonEmpty) {
          val lastNode = elems.last
          val fileName = fileOf(lastNode)
          if (fileName.nonEmpty) {
            val n = elems.size
            // 구조화된 path (라인 + 코드 + 역할). 최대 12스텝.
            val steps: List[Step] = elems.zipWithIndex.take(12).map { case (e, i) =>
              val role = if (i == 0) "source" else if (i == n - 1) "sink" else "intermediate"
              Step(lineOf(e), e.code.take(200), role)
            }.toList
            // sanitizer 검사 — flow 의 모든 노드를 본다(파일 상단 _role_note 참조)
            val hits: List[SanHit] = elems.zipWithIndex.flatMap { case (e, i) =>
              val role = if (i == 0) "source" else if (i == n - 1) "sink" else "intermediate"
              val cands = enclosingCodes(e)
              pats.flatMap { p =>
                cands.find(c => try p.matcher(c).find() catch { case _: Throwable => false })
                     .map(c => SanHit(lineOf(e), c.take(200), role, p.pattern))
              }
            }.toList
            findings ::= Finding(
              fileName, r.cat, r.cwe,
              elems.head.code.take(160), lastNode.code.take(160), lineOf(lastNode),
              steps, hits.nonEmpty, hits.take(6)
            )
          }
        }
      }
    } catch { case e: Throwable => System.err.println(s"[rule ${r.cat}] ${e.toString.take(200)}") }
  }

  // presence 규칙
  for (p <- PRESENCE_RULES) {
    try {
      val nodes: List[io.shiftleft.codepropertygraph.generated.nodes.AstNode] =
        if (p.litRe.nonEmpty) cpg.literal.code(p.litRe).l
        else if (p.callRe.nonEmpty) cpg.call.methodFullName(p.callRe).l
        else Nil
      for (n <- nodes) {
        val fileName = fileOf(n)
        val ln = try { n.lineNumber.map(_.toInt).getOrElse(-1) } catch { case _: Throwable => -1 }
        if (fileName.nonEmpty)
          findings ::= Finding(fileName, p.cat, p.cwe, n.code.take(120), n.code.take(120),
                               ln, List(Step(ln, n.code.take(200), "sink")), false, Nil)
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
    val pathJson = f.path.map(s =>
      s"""{"line":${s.line},"code":"${esc(s.code)}","role":"${esc(s.role)}"}""").mkString(",")
    val hitsJson = f.sanHits.map(h =>
      s"""{"line":${h.line},"code":"${esc(h.code)}","role":"${esc(h.role)}","pattern":"${esc(h.pattern)}"}""")
      .mkString(",")
    s"""{"file":"${esc(f.file)}","category":"${esc(f.cat)}","cwe":"${esc(f.cwe)}",""" +
    s""""source":"${esc(f.src)}","sink":"${esc(f.snk)}","line":${f.line},""" +
    s""""sanitized":${f.sanitized},"sanitizer_hits":[${hitsJson}],""" +
    s""""path":[${pathJson}]}"""
  }.mkString(","))
  out.append("]}")

  java.nio.file.Files.write(java.nio.file.Paths.get(outFile), out.toString.getBytes)

  // workspace 누수 방지 — 청크 CPG를 반드시 닫고 지운다
  try { close(proj) } catch { case _: Throwable => () }
  try { delete(proj) } catch { case _: Throwable => () }
}
