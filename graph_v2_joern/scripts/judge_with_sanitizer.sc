// 지난번 발견한 gap 보완: source→sink 경로가 있어도, 그 경로 중간에
// sanitizer(안전처리 함수)가 껴있으면 "안전"으로 판정해야 하는데,
// taint_test*.sc 들은 이 체크가 없었음 (경로 존재=무조건 취약 으로만 판단했음).
//
// 이 스크립트는 재사용 가능한 함수(judge)로 만들어서, 앞으로 어떤 케이스든
// 이 로직 하나로 판정하게 함.
//
// 판정 규칙 (설계했던 원래 규칙 그대로):
//   경로 없음                    → unknown
//   경로 있음 + sanitizer 없음   → vuln
//   경로 있음 + sanitizer 있음   → safe

importCpg("C:/Users/user/Desktop/graph-experiment/juiceshop.cpg.bin")
import io.joern.dataflowengineoss.language._
import io.shiftleft.codepropertygraph.generated.nodes.AstNode

// 알려진 sanitizer 패턴들 (multi_graph.py의 SANITIZERS 개념을 Joern 쪽에도 적용)
val SANITIZER_PATTERNS = List(
  "escapeHtml", "sanitizeHtml", "sanitizeSecure", "sanitizeLegacy",
  "encodeForHTML", "DOMPurify", "\\.setString\\(", "\\.setInt\\(",
  "isRedirectAllowed", "allowlist", "escapeshellarg", "parameterize"
)

def judge(sinkNodes: List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode],
          sourceNodes: List[io.shiftleft.codepropertygraph.generated.nodes.CfgNode],
          label: String): Unit = {
  println(s"\n========== 판정 대상: $label ==========")
  if (sinkNodes.isEmpty || sourceNodes.isEmpty) {
    println("  sink 또는 source 후보 없음 → 스킵")
    return
  }
  val flows = sinkNodes.reachableByFlows(sourceNodes).l
  if (flows.isEmpty) {
    println(s"  판정: UNKNOWN (source→sink 경로 자체가 없음)")
    return
  }

  // 각 flow의 경로 안에 sanitizer 패턴이 하나라도 있는지 확인
  val flowsWithSanitizer = flows.filter { flow =>
    flow.elements.exists(e => SANITIZER_PATTERNS.exists(p => e.code.matches(s".*$p.*")))
  }

  if (flowsWithSanitizer.size == flows.size) {
    println(s"  판정: SAFE (경로 ${flows.size}개 전부 sanitizer를 거쳐감)")
  } else if (flowsWithSanitizer.isEmpty) {
    println(s"  판정: VULN (경로 ${flows.size}개, sanitizer 거치는 경로 0개)")
  } else {
    println(s"  판정: VULN (경로 ${flows.size}개 중 ${flows.size - flowsWithSanitizer.size}개는 sanitizer 없이 도달 — 일부 우회 가능)")
  }
}

// ── V1: login.ts SQLi (sanitizer 없어야 정상) ──────────────────────────────
judge(
  cpg.call.methodFullName(".*sequelize.*query.*").where(_.file.name(".*login.ts")).l,
  cpg.identifier.name("req").where(_.file.name(".*login.ts")).l ++
    cpg.call.code(".*req\\.body\\.email.*").where(_.file.name(".*login.ts")).l,
  "V1 login.ts SQLi"
)

// ── V3: fileUpload.ts → xml.ts XXE (sanitizer 없어야 정상) ─────────────────
judge(
  cpg.call.code(".*runInContext.*").where(_.file.name(".*lib.xml.ts")).l,
  cpg.call.code(".*file\\.buffer.*").where(_.file.name(".*routes.fileUpload.ts")).l ++
    cpg.identifier.name("data").where(_.file.name(".*routes.fileUpload.ts")).l,
  "V3 fileUpload.ts→xml.ts XXE"
)

// ── redirect.ts: isRedirectAllowed라는 체크가 있는 케이스 (참고용 테스트) ──
judge(
  cpg.call.code(".*res\\.redirect\\(toUrl\\).*").where(_.file.name(".*routes.redirect.ts")).l,
  cpg.call.code(".*query\\.to.*").where(_.file.name(".*routes.redirect.ts")).l,
  "redirect.ts open redirect (isRedirectAllowed 있음, 참고용)"
)
