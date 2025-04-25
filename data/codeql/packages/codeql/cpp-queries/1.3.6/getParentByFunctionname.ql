
import cpp

private predicate hasBody(Function f) { exists(Stmt s | s.getEnclosingFunction() = f) }

private int maxEndLineOfBody(Function f) {
  result = max(Stmt s | s.getEnclosingFunction() = f | s.getLocation().getEndLine())
}

private int getRealEndLine(Function f) {
  result = maxEndLineOfBody(f) and hasBody(f)
  or
  result = f.getLocation().getEndLine() and not hasBody(f)
}

from Function f, Function g
where
  f.getName() = "process_sqliterc" and
  g = f.getACallToThisFunction().getEnclosingFunction()
select g.getName(), g.getAFile().getAbsolutePath(), g.getLocation().getStartLine(), getRealEndLine(g)
    