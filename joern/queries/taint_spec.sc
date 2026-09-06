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
 *   sink<TAB>cat<TAB>cwe<TAB>field(name|full|code|assign_field|dynamic_index|exists|exists_full|arg_literal|arg_literal_full|arg_count|arg_count_full)<TAB>regex[<TAB>argRegex]
 *   source<TAB>-<TAB>-<TAB>field(name|full)<TAB>regex
 * field=assign_field (PLAN.md 4단계): `el.innerHTML = x` 같은 프로퍼티 대입을 sink 로 본다.
 * regex 는 대입 LHS 의 필드명(예: innerHTML)에 매칭한다 — 함수 호출이 아니므로 name/full 과는
 * 다른 노드(<operator>.assignment)를 쿼리한다. 후보는 dump_candidates.sc 의 assigns, 라벨은
 * graph_spec_llm.py 가 다른 후보와 같은 반과적합 규칙으로 생성한다.
 * field=exists / exists_full (2026-09-04, §1-11): "danger가 데이터 흐름이 아니라 API 자체에
 * 있는" sink(예: System.loadLibrary, new Random()) — reachableByFlows 없이, 콜이 CPG 안에
 * 존재하면 그 자체로 finding. exists 는 cpg.call.name(regex), exists_full 은
 * cpg.call.methodFullName(regex) 로 콜을 고른다. source 표시는 "N/A (call-site-only)".
 * field=arg_literal / arg_literal_full (2026-09-04, §1-11): 인자 값 자체가 위험 신호인
 * sink(예: Cipher.getInstance("DES"), Cookie.setMaxAge(양수)) — regex(5번째 열)로 콜을
 * 고르는 건 exists 와 같고(arg_literal 은 name, arg_literal_full 은 full), 거기에 6번째 열
 * argRegex 를 추가로 요구해 그 콜의 argumentIndex>0 인자 중 하나의 .code 가 argRegex 와
 * 매칭될 때만 finding. reachableByFlows 는 쓰지 않는다(source 표시는 "N/A (arg-literal-only)").
 * field=arg_count / arg_count_full (2026-09-05, 3라운드 §5): bad/good 이 같은 이름의 서로
 * 다른 오버로드(인자 개수만 다름, 예: String.getBytes(4-인자) vs getBytes("UTF-8"))일 때 —
 * 콜 선택은 arg_literal 과 같고(name/full), 6번째 열을 여기선 정규식이 아니라 "요구하는
 * argumentIndex>0 개수"(정수 문자열)로 재해석해서, 그 개수와 정확히 같은 콜만 finding.
 * reachableByFlows 안 씀(source 표시는 "N/A (arg-count-only)").
 * 6번째 열은 옵션이라 기존 5열짜리 스펙 행은 그대로 호환된다.
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

case class Rule(cat: String, cwe: String, sink: String, field: String, argRe: String = "")
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
    // limit=6: arg_literal(_full) 룰은 6번째 열(argRegex)을 쓴다. 기존 5열 행은 limit 을 늘려도
    // 탭이 4개뿐이라 그대로 5개짜리 배열이 나와 호환된다(2026-09-04, §1-11).
    val p = ln.split("\t", 6)
    if (p.length >= 5) {
      if (p(0) == "sink") {
        val argRe = if (p.length >= 6) p(5) else ""
        rules = rules :+ Rule(p(1), p(2), p(4), p(3), argRe)
      }
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
                     line: Int, srcFile: String, srcLine: Int, srcKind: String,
                     path: List[Step], sanitized: Boolean, sanHits: List[SanHit],
                     rulePat: String, ruleField: String)
  var findings = List.empty[Finding]

  // source = 명시적 파라미터(암묵 수신자 제외) + 스펙이 지정한 source 호출.
  // srcMode="calls"는 source API call만 사용한다. Java 제품 경로에서 모든 메서드
  // 파라미터를 attacker input으로 보니 HttpServletResponse까지 source가 되어 sink receiver
  // 쪽 가짜 경로가 실제 cross-file 경로를 덮는 문제가 있어 추가했다. 기존 params/r2/r2chain
  // 동작은 그대로 유지한다.
  val allExplicitParams = cpg.method.parameter.nameNot("self", "this", "cls").l
  def isDataCarrierType(t: String): Boolean =
    t.matches("(?i).*(String|CharSequence|byte\\[\\]|char\\[\\]|Path|File|URI|URL|InputStream|Reader|Map|List|Collection|Object).*")
  def isFrameworkContextType(t: String): Boolean =
    t.matches("(?i).*(HttpServletResponse|ServletResponse|HttpServletRequest|ServletRequest|ApplicationContext|SecurityContext|Logger).*")
  def isPublicDataParam(p: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn): Boolean = {
    // Joern's Java frontend stores visibility in MODIFIER.modifierType ("PUBLIC");
    // MODIFIER.code is the sentinel "<empty>" and must not be used here.
    val publicMethod = try p.method.modifier.modifierType.l.exists(_.toString.equalsIgnoreCase("PUBLIC"))
                       catch { case _: Throwable => false }
    val t = try p.typeFullName catch { case _: Throwable => "" }
    publicMethod && isDataCarrierType(t) && !isFrameworkContextType(t)
  }
  val paramSources =
    if (srcMode == "calls") Nil
    else if (srcMode == "java") allExplicitParams.filter(isPublicDataParam)
    else allExplicitParams
  val callSources = srcRules.flatMap { s =>
    try { if (s.field == "full") cpg.call.methodFullName(s.re).l else cpg.call.name(s.re).l }
    catch { case _: Throwable => Nil }
  }.distinct
  // Java frontends do not connect constructor/setter parameter writes to later reads of
  // the same instance field.  Treat data-carrying `this.field` reads as trust-boundary
  // continuations; sink reachability still has to hold, so the field read alone is not a finding.
  val javaStateSources =
    if (srcMode != "java") Nil
    else try cpg.call.name("<operator>.fieldAccess").l.filter { c =>
      val t = try c.typeFullName catch { case _: Throwable => "" }
      c.code.trim.startsWith("this.") && isDataCarrierType(t) && !isFrameworkContextType(t)
    } catch { case _: Throwable => Nil }

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

  val sources = paramSources ++ callSources ++ faSources ++ javaStateSources

  // 2026-09-04 dangerous-call-only 확장(§1-11) 전용 헬퍼: exists/arg_literal 은 flow path 가
  // 없어 콜 노드 하나만 보고 sanitizer 근접 여부를 판단한다. 기존 reachability 분기(아래 else)의
  // hits 계산과는 별개 코드 경로 — 기존 로직은 손대지 않는다.
  def sanHitsForCall(c: Call, pats: List[java.util.regex.Pattern]): List[SanHit] = {
    val cands = enclosingCodes(c)
    pats.flatMap { p =>
      cands.find(cc => try p.matcher(cc).find() catch { case _: Throwable => false })
           .map(cc => SanHit(lineOf(c), cc.take(200), "sink", p.pattern))
    }
  }

  var ruleErrors = List.empty[String]
  for (r <- rules) {
    try {
      if (r.field == "exists" || r.field == "exists_full") {
        // (a) 순수 존재확인: source→sink 데이터 흐름이 아니라 API 호출 자체가 위험 신호인 sink
        // (System.loadLibrary, new Random() 등). reachableByFlows 없이 콜이 CPG 에 있으면 finding.
        val calls = if (r.field == "exists_full") cpg.call.methodFullName(r.sink).l else cpg.call.name(r.sink).l
        val pats = sanPatternsFor(r.cat)
        for (c <- calls) {
          val fileName = fileOf(c)
          if (fileName.nonEmpty) {
            val hits = sanHitsForCall(c, pats)
            findings ::= Finding(
              fileName, r.cat, r.cwe,
              "N/A (call-site-only)", c.code.take(160), lineOf(c),
              fileName, lineOf(c), "call_site_only",
              List(Step(fileName, lineOf(c), c.code.take(200), "sink")),
              hits.nonEmpty, hits.take(6), r.sink, r.field)
          }
        }
      } else if (r.field == "arg_literal" || r.field == "arg_literal_full") {
        // (b) 인자 리터럴 정규식: 콜은 존재확인과 같은 방식(name/full)으로 고르되, argumentIndex>0
        // 인자 중 하나의 .code 가 argRe 와 매칭될 때만 finding. reachableByFlows 는 안 쓴다.
        val calls = if (r.field == "arg_literal_full") cpg.call.methodFullName(r.sink).l else cpg.call.name(r.sink).l
        val argPat = try Some(java.util.regex.Pattern.compile(r.argRe)) catch { case _: Throwable => None }
        val pats = sanPatternsFor(r.cat)
        argPat.foreach { ap =>
          for (c <- calls) {
            val hasMatchingArg = c.argument.filter(_.argumentIndex > 0).l
              .exists(a => try ap.matcher(a.code).find() catch { case _: Throwable => false })
            if (hasMatchingArg) {
              val fileName = fileOf(c)
              if (fileName.nonEmpty) {
                val hits = sanHitsForCall(c, pats)
                findings ::= Finding(
                  fileName, r.cat, r.cwe,
                  "N/A (arg-literal-only)", c.code.take(160), lineOf(c),
                  fileName, lineOf(c), "argument_literal",
                  List(Step(fileName, lineOf(c), c.code.take(200), "sink")),
                  hits.nonEmpty, hits.take(6), r.sink, r.field)
              }
            }
          }
        }
      } else if (r.field == "arg_count" || r.field == "arg_count_full") {
        // (c) 인자 개수(arity) 매칭: 2026-09-05 3라운드 §5(CWE-477) -- bad/good 이 같은 클래스·
        // 같은 메서드 이름의 서로 다른 오버로드일 때(예: String.getBytes(4-인자) vs
        // getBytes("UTF-8"), URLEncoder.encode(1-인자) vs encode(2-인자)), 이름/인자값만으론
        // 못 가르고 인자 "개수"로만 구분된다(실측: exists 로 하면 안전한 오버로드까지 전부
        // 걸림 -- SUMMARY 참고). 콜 선택은 exists/arg_literal 과 동일(name/full), argRe 열은
        // 여기선 정규식이 아니라 "요구하는 정확한 argumentIndex>0 개수"(정수 문자열)로 재해석.
        // reachableByFlows 안 씀.
        val calls = if (r.field == "arg_count_full") cpg.call.methodFullName(r.sink).l else cpg.call.name(r.sink).l
        val wantCount = try Some(r.argRe.trim.toInt) catch { case _: Throwable => None }
        val pats = sanPatternsFor(r.cat)
        wantCount.foreach { n =>
          for (c <- calls) {
            val argCount = c.argument.filter(_.argumentIndex > 0).size
            if (argCount == n) {
              val fileName = fileOf(c)
              if (fileName.nonEmpty) {
                val hits = sanHitsForCall(c, pats)
                findings ::= Finding(
                  fileName, r.cat, r.cwe,
                  "N/A (arg-count-only)", c.code.take(160), lineOf(c),
                  fileName, lineOf(c), "argument_count",
                  List(Step(fileName, lineOf(c), c.code.take(200), "sink")),
                  hits.nonEmpty, hits.take(6), r.sink, r.field)
              }
            }
          }
        }
      } else {
      val sinks =
        if (r.field == "full") cpg.call.methodFullName(r.sink).argument.filter(_.argumentIndex > 0)
        else if (r.field == "code") cpg.call.code(r.sink).argument.filter(_.argumentIndex > 0)
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
        else cpg.call.name(r.sink).argument.filter(_.argumentIndex > 0)
      val flows = sinks.reachableByFlows(sources).l
      val pats = sanPatternsFor(r.cat)
      for (f <- flows) {
        val elems = f.elements
        if (elems.nonEmpty) {
          val lastNode = elems.last
          // 2026-09-02 sink-argument-fix: lastNode가 인자 노드면 부모 CALL의 코드를
          // 대신 보여준다 (void 반환 sink 버그 수정의 표시용 보정, §10 로그 참고)
          val sinkDisplayCode: String = try {
            val p = lastNode.astParent
            if (p != null && p.isInstanceOf[Call]) p.code else lastNode.code
          } catch { case _: Throwable => lastNode.code }
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
            val srcKind =
              if (paramSources.exists(_.id == elems.head.id)) "public_parameter"
              else if (callSources.exists(_.id == elems.head.id)) "explicit_source_api"
              else if (javaStateSources.exists(_.id == elems.head.id)) "instance_state"
              else if (faSources.exists(_.id == elems.head.id)) "parameter_field_access"
              else "unknown"
            findings ::= Finding(
              fileName, r.cat, r.cwe,
              elems.head.code.take(160), sinkDisplayCode.take(160), lineOf(lastNode),
              fileOf(elems.head), lineOf(elems.head), srcKind,
              steps, hits.nonEmpty, hits.take(6), r.sink, r.field)
          }
        }
      }
      }
    } catch {
      case e: Throwable =>
        ruleErrors = ruleErrors :+ s"${r.cat}|${r.sink.take(60)}|${e.toString.take(120)}"
    }
  }

  val dedupedFindings = findings
    .groupBy(f => (f.file, f.cat, f.cwe, f.line))
    .map(_._2.head)
    .toList
  // 2026-09-02 sink-argument-fix: argument 단위로 sink를 잡으면 콜 하나(예: println(str))가
  // 인자 여러 개(receiver 포함) 각각에서 중복 검출될 수 있어 (file,cat,cwe,line) 기준으로 합친다.
  // 2026-09-02 sink-argument-fix(추가): receiver(argumentIndex=0, 예: writer.println()의 writer)는
  // "sink 로 값이 들어가는 인자"가 아니라 "메서드를 호출하는 객체"라 sink 후보에서 제외한다
  // (필터 전: writer 자체가 오염된 것처럼 잘못 표시되는 flow 가 섞여 나왔다, §10 로그 참고).

  val sb = new StringBuilder
  sb.append(s"""{"arm":"${esc(arm)}","n_rules":${rules.size},"n_source_rules":${srcRules.size},""")
  sb.append(s""""n_prop_rules":${propFlows.size},"n_sanitizer_patterns":${sanAll.size},""")
  sb.append(s""""n_call_sources":${callSources.size},"n_param_sources":${paramSources.size},""")
  sb.append(s""""n_java_state_sources":${javaStateSources.size},""")
  sb.append(s""""src_mode":"${esc(srcMode)}","n_fieldaccess_sources":${faSources.size},""")
  sb.append("\"parsed\":[")
  sb.append(methodFiles.toList.sorted.map(f => "\"" + esc(f) + "\"").mkString(","))
  sb.append("],\"seen\":[")
  sb.append((parsedFiles ++ methodFiles).toList.sorted.map(f => "\"" + esc(f) + "\"").mkString(","))
  sb.append("],\"rule_errors\":[")
  sb.append(ruleErrors.take(50).map(x => "\"" + esc(x) + "\"").mkString(","))
  sb.append("],\"findings\":[")
  sb.append(dedupedFindings.map { f =>
    val pathJson = f.path.map(s =>
      s"""{"file":"${esc(s.file)}","line":${s.line},"code":"${esc(s.code)}","role":"${esc(s.role)}"}""")
      .mkString(",")
    val hitsJson = f.sanHits.map(h =>
      s"""{"line":${h.line},"code":"${esc(h.code)}","role":"${esc(h.role)}","pattern":"${esc(h.pattern)}"}""")
      .mkString(",")
    s"""{"file":"${esc(f.file)}","category":"${esc(f.cat)}","cwe":"${esc(f.cwe)}",""" +
    s""""source":"${esc(f.src)}","sink":"${esc(f.snk)}","line":${f.line},""" +
    s""""source_file":"${esc(f.srcFile)}","source_line":${f.srcLine},""" +
    s""""source_kind":"${esc(f.srcKind)}",""" +
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
