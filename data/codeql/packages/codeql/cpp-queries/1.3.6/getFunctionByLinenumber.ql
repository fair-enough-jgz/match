
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

from Function f, File file
where file.getAbsolutePath() = "/home/jgz/data/code/sqlite/shell.c" 
and f.getLocation().getStartLine() <= 24647 
and getRealEndLine(f) >= 24647
select f.getName(), f.getAFile().getAbsolutePath(), f.getLocation().getStartLine(), getRealEndLine(f)
    