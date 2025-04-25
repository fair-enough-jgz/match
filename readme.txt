./configure --enable-debug "CFLAGS=-O0 -g -fsanitize=signed-integer-overflow"

make sqlite3

codeql database finalize -- /home/vulmine/data/db/sqlite3