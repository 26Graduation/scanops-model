// ① 후보 API 추출 스크립트
// 목적: 이 레포 코드 안에서 "어떤 함수/메서드들이 호출되는지" 전부 뽑아낸다.
// 이걸 뽑아내는 이유: 나중에 LLM이 "이 중 어떤 게 위험한 sink인지" 라벨링하려면
// 먼저 "뭐가 있는지" 목록이 있어야 하기 때문. 사람이 미리 알려주지 않는다.
//
// 사용법: joern --script extract_candidates.sc
// (Windows에서 --param 전달이 꼬여서 경로는 아래에 직접 하드코딩)

val cpgPathParam = "C:/Users/user/Desktop/graph-experiment/juiceshop.cpg.bin"
val outPathParam = "C:/Users/user/Desktop/graph-experiment/candidates_raw.json"

importCpg(cpgPathParam)

// <operator>.xxx 는 그냥 +,-,=,. 같은 언어 기본 연산자라 "API"가 아님 → 제외
// 이런 노이즈를 걸러내야 진짜 함수 호출(외부 라이브러리든 자기 코드든)만 남음
val calls = cpg.call
  .filterNot(_.name.startsWith("<operator>"))
  .filterNot(_.name == "<unknown>")
  .l

// 같은 이름의 호출이 여러 번 나올 수 있으니, 이름 기준으로 묶어서
// "이 함수가 코드 어디서 어떻게 쓰이는지" 예시 하나씩만 남긴다.
case class Candidate(name: String, methodFullName: String, exampleCode: String,
                       exampleFile: String, exampleLine: Int, occurrences: Int)

val grouped = calls.groupBy(_.name).map { case (name, group) =>
  val first = group.head
  Candidate(
    name = name,
    methodFullName = first.methodFullName,
    exampleCode = first.code.take(120),
    exampleFile = first.file.name.headOption.getOrElse(""),
    exampleLine = first.lineNumber.getOrElse(-1),
    occurrences = group.size
  )
}.toList.sortBy(-_.occurrences)

println(s"=== 총 서로 다른 호출 이름 수: ${grouped.size} ===")

// JSON으로 직접 조립 (외부 라이브러리 없이, 문자열로)
def esc(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ")
val json = grouped.map { c =>
  s"""{"name":"${esc(c.name)}","methodFullName":"${esc(c.methodFullName)}","exampleCode":"${esc(c.exampleCode)}","exampleFile":"${esc(c.exampleFile)}","exampleLine":${c.exampleLine},"occurrences":${c.occurrences}}"""
}.mkString("[\n  ", ",\n  ", "\n]")

import java.io.PrintWriter
val pw = new PrintWriter(outPathParam)
pw.write(json)
pw.close()

println(s"저장 완료: ${outPathParam}")
println("=== 상위 30개 미리보기 (많이 쓰인 순) ===")
grouped.take(30).foreach(c => println(s"  ${c.name}  (${c.occurrences}회)  예시: ${c.exampleCode}"))
