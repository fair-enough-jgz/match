
import cpp

from MacroInvocation mi
where exists(int i | mi.getExpandedArgument(i).toString() = "process_sqliterc")
select mi.getMacroName(), mi.getFile().getAbsolutePath(), mi.getLocation().getStartLine(),
  mi.getLocation().getEndLine()
    