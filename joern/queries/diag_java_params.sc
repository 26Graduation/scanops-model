import io.joern.console.*
import io.joern.console.cpgcreation.*
import io.shiftleft.semanticcpg.language.*

@main def exec(inDir: String): Unit = {
  importCode.java(inDir, "java-param-diag")
  cpg.method.parameter.nameNot("self", "this", "cls").l.foreach { p =>
    val method = p.method
    val modifiers = method.modifier.l.map { m =>
      val code = try m.code catch { case _: Throwable => "" }
      val kind = try m.modifierType catch { case _: Throwable => "" }
      s"code=$code,type=$kind"
    }.mkString(";")
    println(s"PARAM|method=${method.fullName}|name=${p.name}|type=${p.typeFullName}|modifiers=$modifiers")
  }
}
