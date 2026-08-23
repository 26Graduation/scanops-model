/*
 * ScanOps — GRAPH-SPEC 라운드 §5-3/§5-4: **스펙 주입형 taint 쿼리**
 * =================================================================
 * `taint_v4.sc` 는 손으로 쓴 룰 21개를 **코드 안에** 갖고 있다. 이 파일은 그 룰을
 * **밖에서 파일로 주입**받는다. arm 을 바꾸는 방법이 스펙 파일 교체 하나뿐이 되도록.
 *
 *   S2-A : specFile = 손 룰 21개를 그대로 옮긴 스펙
 *   S2-B : specFile = LLM 생성 스펙
 *   S2-C : specFile = 둘의 합집합 (§4-1 병합 규칙은 파이썬에서 적용)
 *
 * taint_v4.sc 와의 의도적 차이(측정에 필요한 것만):
 *   - 파일 키를 basename 이 아니라 **inDir 기준 상대경로**로 낸다. 라인 단위 채점(§6)에
 *     basename 은 못 쓴다(중복 basename 이 있다).
 *   - 룰이 하드코딩이 아니라 specFile 에서 온다.
 *   - source 도 스펙에서 온다(파라미터 source 는 유지 — 이건 엔진 기본값이다).
 *   - propFile 이 주어지면 CPGHunter 식 **인자→반환 오염 전파 규칙**을 EngineContext 에 싣는다.
 * 그 외 sanitizer 처리·path 출력·에러 처리는 taint_v4.sc 와 같은 방식을 따른다.
 *
 * specFile 형식 (TSV, 한 줄 = 룰 하나):
 *   sink<TAB>cat<TAB>cwe<TAB>field(name|full|assign_field|dynamic_index)<TAB>regex
 *   source<TAB>-<TAB>-<TAB>field(name|full)<TAB>regex
 * field=assign_field (PLAN.md 4단계): `el.innerHTML = x` 같은 프로퍼티 대입을 sink 로 본다.
 * regex 는 대입 LHS 의 필드명(예: innerHTML)에 매칭한다 — 함수 호출이 아니므로 name/full 과는
 * 다른 노드(<operator>.assignment)를 쿼리한다. 후보는 dump_candidates.sc 의 assigns, 라벨은
 * graph_spec_llm.py 가 다른 후보와 같은 반과적합 규칙으로 생성한다.
 * sanFile 형식은 taint_v4.sc 와 동일 (3열: 블록카테고리 / applies_to / regex)
 * propFile 형식 (TSV):
 *   methodFullNameRegex<TAB>src,dst;src,dst;...      (src/dst: 정수 또는 "return")
 */

import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.joern.dataflowengineoss.semanticsloader.{FlowSemantic, FullNameSemantics}
import io.joern.dataflowengineoss.DefaultSemantics
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.codepropertygraph.generated.nodes.Literal

case class Rule(cat: String, cwe: String, sink: String, field: String)
case class SrcRule(field: String, re: String)

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

def readLines(p: String): List[String] =
  if (p.isEmpty) Nil
  else try {
    val s = scala.io.Source.fromFile(p, "UTF-8")
    try s.getLines().toList finally s.close()
  } catch { case _: Throwable => Nil }

/* 2라운드 STEP 5: srcMode
 *   "params" (기본) = 1라운드 동작 그대로. 재현성 보존용.
 *   "r2"            = params + **파라미터에 뿌리내린 <operator>.fieldAccess**
 *   "r2chain"       = r2 + <operator>.indexAccess 도 같은 규칙으로 source 에 포함
 * "r2" 근거는 rebuild/out/graph_spec_jssrc_diag_r2.json 의 실측이다:
 * JSSRC 는 METHOD_PARAMETER_IN 과 `param.a.b` fieldAccess 사이에 데이터 의존 엣지를
 * 만들지 않아, 파라미터만 source 로 쓰면 flows=0 이 된다.
 * "r2chain" 근거는 PLAN.md 3.5단계 최소재현(t1~t9, /tmp/probe_fittr/repro/)이다:
 * `data.a`(1단계)는 흐르는데 `data.a.b`(2단계 이상, fieldAccess·indexAccess 조합 무관)는
 * 흐르지 않는다 — JSSRC 는 한 문장 안에서 <operator>.fieldAccess/indexAccess 가 2단계 이상
 * 이어지면 DDG 엣지를 안 만든다(체인 깊이 문제, 인덱스 접근 자체의 문제가 아님).
 * "r2" 는 fieldAccess 만 보므로 인덱스 접근이 섞인 체인(`data.a.b[i]`)을 놓친다.
 * "r2" 를 고치지 않고 새 모드로 추가한 것은 §11/§14 박제 결과(FROZEN)의 재현성을 지키기 위함 —
 * "r2" 로 재실행하면 이전과 바이트 단위로 같은 결과가 나와야 한다. */
@main def exec(inDir: String, lang: String, outFile: String, specFile: String,
               sanFile: String = "", propFile: String = "", arm: String = "?",
               srcMode: String = "params"): Unit = {
  val proj = "spec"

  // ── 스펙 로드 ──────────────────────────────────────────────────────────────
  var rules = List.empty[Rule]
  var srcRules = List.empty[SrcRule]
  for (ln <- readLines(specFile)) {
    val p = ln.split("\t", 5)
    if (p.length == 5) {
      if (p(0) == "sink") rules = rules :+ Rule(p(1), p(2), p(4), p(3))
      else if (p(0) == "source") srcRules = srcRules :+ SrcRule(p(3), p(4))
    }
  }

  case class SanPat(applies: Set[String], p: java.util.regex.Pattern)
  val sanAll: List[SanPat] = readLines(sanFile).flatMap { ln =>
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
  def sanPatternsFor(cat: String): List[java.util.regex.Pattern] =
    sanAll.filter(sp => sp.applies.contains("*") || sp.applies.contains(cat)).map(_.p)

  // ── 오염 전파 규칙 (CPGHunter) ─────────────────────────────────────────────
  // 규칙이 없는 메서드는 Joern 기본대로 전부 전파된다. 여기 실린 것만 **한정**된다.
  val propFlows: List[FlowSemantic] = readLines(propFile).flatMap { ln =>
    val p = ln.split("\t", 2)
    if (p.length < 2) None
    else {
      val maps = p(1).split(";").toList.flatMap { m =>
        val kv = m.split(",")
        if (kv.length != 2) None
        else {
          def idx(s: String): Option[Int] =
            if (s.trim == "return") Some(-1) else try Some(s.trim.toInt) catch { case _: Throwable => None }
          for (a <- idx(kv(0)); b <- idx(kv(1))) yield (a, b)
        }
      }
      if (maps.isEmpty) None
      else try Some(FlowSemantic.from(p(0), maps, true)) catch { case _: Throwable => None }
    }
  }

  try {
    importCode(inputPath = inDir, projectName = proj, language = lang)
  } catch {
    case e: Throwable =>
      java.nio.file.Files.write(java.nio.file.Paths.get(outFile),
        s"""{"error":"import_failed","message":"${esc(e.toString.take(400))}","findings":[]}""".getBytes)
      return
  }

  /* Scala 3: `operatorFlows()` 는 반환된 List 에 apply(n) 을 거는 것으로 읽힌다 → 괄호 없이 쓴다.
   * EngineContext 는 (semantics, config) 두 인자를 받는다 → 기본 config 를 그대로 재사용한다. */
  val baseCtx = EngineContext()
  implicit val engineContext: EngineContext =
    if (propFlows.isEmpty) baseCtx
    else EngineContext(FullNameSemantics.fromList(DefaultSemantics.operatorFlows ++ propFlows),
                       baseCtx.config)

  // inDir 접두를 떼어 상대경로 키를 만든다
  val base = { val b = inDir.stripSuffix("/"); b + "/" }
  def relOf(s: String): String = if (s.startsWith(base)) s.substring(base.length) else s

  val parsedFiles: Set[String] =
    cpg.file.name.l.filter(_.nonEmpty).map(relOf).toSet
  val methodFiles: Set[String] =
    cpg.method.filter(_.filename.nonEmpty).map(m => relOf(m.filename)).l.toSet

  def fileOf(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): String =
    try { val v = n.file.name.l; if (v.nonEmpty) relOf(v.head) else "" }
    catch { case _: Throwable => "" }

  def lineOf(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Int =
    try { n.lineNumber.map(_.toInt).getOrElse(-1) } catch { case _: Throwable => -1 }

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

  case class Step(file: String, line: Int, code: String, role: String)
  case class SanHit(line: Int, code: String, role: String, pattern: String)
  case class Finding(file: String, cat: String, cwe: String, src: String, snk: String,
                     line: Int, srcFile: String, srcLine: Int,
                     path: List[Step], sanitized: Boolean, sanHits: List[SanHit],
                     rulePat: String, ruleField: String)
  var findings = List.empty[Finding]

  // source = 명시적 파라미터(암묵 수신자 제외) + 스펙이 지정한 source 호출
  val paramSources = cpg.method.parameter.nameNot("self", "this", "cls").l
  val callSources = srcRules.flatMap { s =>
    try { if (s.field == "full") cpg.call.methodFullName(s.re).l else cpg.call.name(s.re).l }
    catch { case _: Throwable => Nil }
  }.distinct

  /* srcMode="r2": 파라미터에 뿌리내린 fieldAccess 를 source 에 더한다.
   * 뿌리 = 노드 code 의 맨 앞 식별자. `req.query.q` -> `req`.
   * 그 이름이 **감싸는 메서드의 파라미터**일 때만 source 로 본다. 구조 규칙이고
   * 특정 이름(req 등)을 가정하지 않는다. */
  def rootIdent(code: String): String = {
    val m = "^([A-Za-z_$][A-Za-z0-9_$]*)".r.findFirstMatchIn(code.trim)
    if (m.isDefined) m.get.group(1) else ""
  }
  val faSources =
    if (srcMode != "r2" && srcMode != "r2chain") Nil
    else try {
      val opNamePattern =
        if (srcMode == "r2chain") "<operator>\\.(fieldAccess|indexAccess)" else "<operator>.fieldAccess"
      cpg.call.name(opNamePattern).l.filter { c =>
        val pn = try c.method.parameter.nameNot("self", "this", "cls").name.l.toSet
                 catch { case _: Throwable => Set.empty[String] }
        val r = rootIdent(c.code)
        r.nonEmpty && pn.contains(r)
      }
    } catch { case _: Throwable => Nil }

  val sources = paramSources ++ callSources ++ faSources

  var ruleErrors = List.empty[String]
  for (r <- rules) {
    try {
      val sinks =
        if (r.field == "full") cpg.call.methodFullName(r.sink)
        else if (r.field == "assign_field")
          // PLAN.md 4단계: 대입문 LHS 가 <operator>.fieldAccess 이고 그 필드명이 규칙에 매칭될 때.
          cpg.call.name("<operator>.assignment").filter { a =>
            a.argument.l.headOption.exists { lhs =>
              lhs.isInstanceOf[Call] && lhs.asInstanceOf[Call].name == "<operator>.fieldAccess" &&
              lhs.asInstanceOf[Call].astChildren.l.lastOption.exists(fc => fc.code.matches(r.sink))
            }
          }
        else if (r.field == "dynamic_index")
          // 2026-08-23 새 손 룰(§23): `obj[key] = val` — LHS 가 <operator>.indexAccess 이고
          // 인덱스가 리터럴이 아닌(=변수/표현식인) 대입. 프로토타입 오염(CWE-1321) sink 모양.
          // API 이름 판단이 아니라 구조 패턴이라 pattern 정규식이 없다 — r.sink 를 안 쓴다.
          cpg.call.name("<operator>.assignment").filter { a =>
            a.argument.l.headOption.exists { lhs =>
              lhs.isInstanceOf[Call] && lhs.asInstanceOf[Call].name == "<operator>.indexAccess" &&
              lhs.asInstanceOf[Call].astChildren.l.lastOption.exists(idx => !idx.isInstanceOf[Literal])
            }
          }
        else cpg.call.name(r.sink)
      val flows = sinks.reachableByFlows(sources).l
      val pats = sanPatternsFor(r.cat)
      for (f <- flows) {
        val elems = f.elements
        if (elems.nonEmpty) {
          val lastNode = elems.last
          val fileName = fileOf(lastNode)
          if (fileName.nonEmpty) {
            val n = elems.size
            val steps: List[Step] = elems.zipWithIndex.take(12).map { case (e, i) =>
              val role = if (i == 0) "source" else if (i == n - 1) "sink" else "intermediate"
              Step(fileOf(e), lineOf(e), e.code.take(200), role)
            }.toList
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
              fileOf(elems.head), lineOf(elems.head),
              steps, hits.nonEmpty, hits.take(6), r.sink, r.field)
          }
        }
      }
    } catch {
      case e: Throwable =>
        ruleErrors = ruleErrors :+ s"${r.cat}|${r.sink.take(60)}|${e.toString.take(120)}"
    }
  }

  val sb = new StringBuilder
  sb.append(s"""{"arm":"${esc(arm)}","n_rules":${rules.size},"n_source_rules":${srcRules.size},""")
  sb.append(s""""n_prop_rules":${propFlows.size},"n_sanitizer_patterns":${sanAll.size},""")
  sb.append(s""""n_call_sources":${callSources.size},"n_param_sources":${paramSources.size},""")
  sb.append(s""""src_mode":"${esc(srcMode)}","n_fieldaccess_sources":${faSources.size},""")
  sb.append("\"parsed\":[")
  sb.append(methodFiles.toList.sorted.map(f => "\"" + esc(f) + "\"").mkString(","))
  sb.append("],\"seen\":[")
  sb.append((parsedFiles ++ methodFiles).toList.sorted.map(f => "\"" + esc(f) + "\"").mkString(","))
  sb.append("],\"rule_errors\":[")
  sb.append(ruleErrors.take(50).map(x => "\"" + esc(x) + "\"").mkString(","))
  sb.append("],\"findings\":[")
  sb.append(findings.map { f =>
    val pathJson = f.path.map(s =>
      s"""{"file":"${esc(s.file)}","line":${s.line},"code":"${esc(s.code)}","role":"${esc(s.role)}"}""")
      .mkString(",")
    val hitsJson = f.sanHits.map(h =>
      s"""{"line":${h.line},"code":"${esc(h.code)}","role":"${esc(h.role)}","pattern":"${esc(h.pattern)}"}""")
      .mkString(",")
    s"""{"file":"${esc(f.file)}","category":"${esc(f.cat)}","cwe":"${esc(f.cwe)}",""" +
    s""""source":"${esc(f.src)}","sink":"${esc(f.snk)}","line":${f.line},""" +
    s""""source_file":"${esc(f.srcFile)}","source_line":${f.srcLine},""" +
    s""""rule_pattern":"${esc(f.rulePat)}","rule_field":"${esc(f.ruleField)}",""" +
    s""""sanitized":${f.sanitized},"sanitizer_hits":[${hitsJson}],""" +
    s""""path":[${pathJson}]}"""
  }.mkString(","))
  sb.append("]}")

  java.nio.file.Files.write(java.nio.file.Paths.get(outFile), sb.toString.getBytes)
  println(s"[taint_spec arm=$arm] rules=${rules.size} src=${srcRules.size} prop=${propFlows.size} findings=${findings.size}")

  try { close(proj) } catch { case _: Throwable => () }
  try { delete(proj) } catch { case _: Throwable => () }
}
