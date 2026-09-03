importCpg("C:/Users/user/Desktop/graph-experiment/joern-verify/basic1.cpg.bin")
import io.joern.dataflowengineoss.language._

println("===== 1) getParameter 호출 노드 =====")
println(cpg.call.name("getParameter").l)

println("\n===== 2) println 호출 노드 =====")
println(cpg.call.name("println").l)

println("\n===== 3) '버그 있던 방식' — sink를 콜 노드 자체로 잡음 =====")
val r3 = cpg.call.name("println").reachableByFlows(cpg.call.name("getParameter")).l
println(s"결과 건수: ${r3.size}")
r3.foreach(f => println(f.elements.map(_.code).mkString(" -> ")))

println("\n===== 4) '수정된 방식' — sink를 인자(.argument)로 잡음 =====")
val r4 = cpg.call.name("println").argument.reachableByFlows(cpg.call.name("getParameter")).l
println(s"결과 건수: ${r4.size}")
r4.foreach(f => println(f.elements.map(_.code).mkString(" -> ")))
