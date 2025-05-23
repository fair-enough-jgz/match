#!/usr/bin/make
# ^^^^ help out editors which guess this file's type.
#
# Makefile for SQLITE
#
# This makefile is intended to be configured automatically using the
# configure script.
#
# The docs for many of its variables are in the primary static
# makefile, main.mk (which this one includes at runtime).
#
all:
########################################################################
#
# Known TODOs/FIXMEs/TOIMPROVEs for the autosetup port, in no
# particular order...
#
# - TEA pieces.
#
# - Replace the autotools-specific distribution deliverable(s).
#
# - Confirm whether cross-compilation works and patch it
# appropriately.
#
# Maintenance reminders:
#
# - This makefile should remain as POSIX-make-compatible as possible:
#   https://pubs.opengroup.org/onlinepubs/9799919799/utilities/make.html
#
# - The naming convention of some vars, using periods instead of
#   underscores, though unconventional, was selected for a couple of
#   reasons: 1) Personal taste (for which there is no accounting).  2)
#   It is thought to help defend against inadvertent injection of
#   those vars via environment variables (because X.Y is not a legal
#   environment variable name).  "Feature or bug?" is debatable and
#   this naming convention may be reverted if it causes any grief.
#

#
# The top-most directory of the source tree.  This is the directory
# that contains this "Makefile.in" and the "configure" script.
#
TOP = /home/jgz/data/code/sqlite

#
# Autotools-conventional vars which are used by package installation
# rules in main.mk. To get sane handling when a user overrides only
# a subset of these, we perform some acrobatics with these vars
# in the configure script: see [proj-remap-autoconf-dir-vars] for
# full details.
#
# For completeness's sake, the aforementioned conventional vars which
# are relevant to our installation rules are:
#
# datadir     = $(prefix)/share
# mandir      = $(datadir)/man
# includedir  = $(prefix)/include
# exec_prefix = $(prefix)
# bindir      = $(exec_prefix)/bin
# libdir      = $(exec_prefix)/lib
#
# Our builds do not require any of their relatives:
#
# sbindir        = $(exec_prefix)/sbin
# sysconfdir     = /etc
# sharedstatedir = $(prefix)/com
# localstatedir  = /var
# runstatedir    = /run
# infodir        = $(datadir)/info
# libexecdir     = $(exec_prefix)/libexec
#
prefix      = /usr/local
datadir     = ${prefix}/share
mandir      = ${datadir}/man
includedir  = ${prefix}/include
exec_prefix = ${prefix}
bindir      = ${exec_prefix}/bin
libdir      = ${exec_prefix}/lib

INSTALL = /usr/bin/install
AR = ar
AR.flags = cr # TODO? Add a configure test to determine this?
CC = cc
B.cc = cc -g
T.cc = $(CC)
#
# $(CFLAGS) is problematic because it is frequently overridden when
# invoking make, which loses things like -fPIC. So... we avoid using
# it directly and instead add a level of indirection.  We combine
# $(CFLAGS) and $(CPPFLAGS) here because that's the way the legacy
# build did it and many builds rely on that. See main.mk for more
# details.
#
# Historical note: the pre-3.48 build only honored CPPFLAGS at
# configure-time, and expanded them into the generated Makefile. There
# are, in that build, no uses of CPPFLAGS in the configure-expanded
# Makefile. Ergo: if a client configures with CPPFLAGS=... and then
# explicitly passes CFLAGS=... to make, the CPPFLAGS will be
# lost. That behavior is retained in 3.48+.
#
CFLAGS = -O2 -g 
#
# $(LDFLAGS.configure) represents any LDFLAGS=... the client passes to
# configure. See main.mk.
#
LDFLAGS.configure = 

#
# CFLAGS.core is documented in main.mk.
#
CFLAGS.core = -fPIC
LDFLAGS.shlib = -shared
LDFLAGS.zlib = -lz
LDFLAGS.math = -lm
LDFLAGS.rpath = -Wl,-rpath,/usr/local/lib
LDFLAGS.pthread = 
LDFLAGS.dlopen = 
LDFLAGS.readline = 
CFLAGS.readline = 
LDFLAGS.icu = 
LDFLAGS.rt = 
CFLAGS.icu = 
LDFLAGS.libsqlite3.soname = 
# soname: see https://sqlite.org/src/forumpost/5a3b44f510df8ded
LDFLAGS.libsqlite3.os-specific =  
# os-specific: see
# - https://sqlite.org/forum/forumpost/9dfd5b8fd525a5d7
# - https://sqlite.org/forum/forumpost/0c7fc097b2
ENABLE_SHARED = 1
ENABLE_STATIC = 1
HAVE_WASI_SDK = 0

T.cc.sqlite = $(T.cc) -DNDEBUG

#
# Define -D_HAVE_SQLITE_CONFIG_H so that the code knows it
# can include the generated sqlite_cfg.h.
#
# main.mk will fill out T.cc.sqlite with additional flags common to
# all builds.
#
T.cc.sqlite += -D_HAVE_SQLITE_CONFIG_H -DBUILD_sqlite

#
# $(JIMSH) and $(CFLAGS.jimsh) are documented in main.mk.  $(JIMSH)
# must start with a path component so that it can be invoked as a
# shell command.
#
CFLAGS.jimsh = -O1 -DHAVE_REALPATH
JIMSH = ./jimsh$(TEXE)

#
# $(B.tclsh) is documented in main.mk.
#
B.tclsh = $(JIMSH)
$(B.tclsh):

#
# $(OPT_FEATURE_FLAGS) is documented in main.mk.
#
# The appending of $(OPTIONS) to $(OPT_FEATURE_FLAGS) is historical
# and somewhat confusing because there's another var, $(OPTS), which
# has a similar (but not identical) role.
#
OPT_FEATURE_FLAGS = -DSQLITE_ENABLE_MATH_FUNCTIONS -DSQLITE_THREADSAFE=1 $(OPTIONS)

#
# Version (X.Y.Z) number for the SQLite being compiled.
#
PACKAGE_VERSION = 3.50.0

#
# Filename extensions for binaries and libraries
#
B.exe = 
T.exe = 
B.dll = .so
T.dll = .so
B.lib = .a
T.lib = .a

#
# $(HAVE_TCL) is 1 if the configure script was able to locate the
# tclConfig.sh file, else it is 0.  When this variable is 1, the TCL
# extension library (libtclsqlite3.so) and related testing apps are
# built.
#
HAVE_TCL = 1

#
# $(TCLSH_CMD) is the command to use for tclsh - normally just
# "tclsh", but we may know the specific version we want to use. This
# must point to a canonical TCL interpreter, not JimTCL.
#
TCLSH_CMD = /usr/bin/tclsh8.6
TCL_CONFIG_SH = /usr/lib/x86_64-linux-gnu/tclConfig.sh

#
# TCL config info from tclConfig.sh
#
# We have to inject this differently in main.mk to accommodate static
# makefiles, so we don't currently bother to export it here. This
# block is retained in case we decide that we do indeed need to export
# it at configure-time instead of calculate it at make-time.
#
#TCL_INCLUDE_SPEC = -I/usr/include/tcl8.6
#TCL_LIB_SPEC = -L/usr/lib/x86_64-linux-gnu -ltcl8.6
#TCL_STUB_LIB_SPEC = -L/usr/lib/x86_64-linux-gnu -ltclstub8.6
#TCL_EXEC_PREFIX = /usr
#TCL_VERSION = 8.6
#
# $(TCLLIBDIR) = where to install the tcl plugin. If this is empty, it
# is calculated at make-time by the targets which need it but we
# export it here so that it can be set at configure-time, so that
# clients are not required to pass it at make-time, or may set it in
# their environment to override it.
#
TCLLIBDIR = /usr/share/tcltk/tcl8.6/sqlite3

#
# Additional options when running tests using testrunner.tcl
# This is usually either blank or --status.
#
TSTRNNR_OPTS = 

#
# If gcov support was enabled by the configure script, add the appropriate
# flags here.  It's not always as easy as just having the user add the right
# CFLAGS / LDFLAGS, because libtool wants to use CFLAGS when linking, which
# causes build errors with -fprofile-arcs -ftest-coverage with some GCCs.
# Supposedly GCC does the right thing if you use --coverage, but in
# practice it still fails.  See:
#
# http://www.mail-archive.com/debian-gcc@lists.debian.org/msg26197.html
#
# for more info.
#
CFLAGS.gcov1 = -DSQLITE_COVERAGE_TEST=1 -fprofile-arcs -ftest-coverage
LDFLAGS.gcov1 = -lgcov
USE_GCOV = 0
T.compile.extras = $(CFLAGS.gcov$(USE_GCOV))
T.link.extras = $(LDFLAGS.gcov$(USE_GCOV))

#
# Vars with the AS_ prefix are specifically related to AutoSetup.
#
# AS_AUTO_DEF is the main configure script.
#
AS_AUTO_DEF = $(TOP)/auto.def
#
# Shell commands to re-run $(TOP)/configure with the same args it was
# invoked with to produce this makefile.
#
AS_AUTORECONFIG = cd /home/jgz/data/code/sqlite && /home/jgz/data/code/sqlite/configure

USE_AMALGAMATION ?= 1
LINK_TOOLS_DYNAMICALLY ?= 0
AMALGAMATION_GEN_FLAGS ?= --linemacros=0

#
# CFLAGS for sqlite3$(T.exe)
#
SHELL_OPT ?= -DSQLITE_HAVE_ZLIB=1

Makefile: $(TOP)/Makefile.in $(AS_AUTO_DEF)
	$(AS_AUTORECONFIG)
	@touch $@

sqlite3.pc: $(TOP)/sqlite3.pc.in $(AS_AUTO_DEF)
	$(AS_AUTORECONFIG)
	@touch $@
install: install-pc # defined in main.mk

sqlite_cfg.h: $(AS_AUTO_DEF)
	$(AS_AUTORECONFIG)
	@touch $@

#
# Fiddle app
#
# EMCC_WRAPPER must refer to the genuine emcc binary, or a
# call-compatible wrapper, e.g. $(TOP)/tool/emcc.sh. If it's empty,
# build components requiring Emscripten will not build.
#
# Achtung: though _this_ makefile is POSIX-make compatible, the fiddle
# build requires GNU make.
#
EMCC_WRAPPER = 
fiddle: sqlite3.c shell.c
	@if [ x = "x$(EMCC_WRAPPER)" ]; then \
		echo "Emscripten SDK not found by configure. Cannot build fiddle." 1&>2; \
		exit 1; \
	fi
	$(MAKE) -C ext/wasm fiddle emcc_opt=-Os

#
# Spell-checking for source comments
# The sources checked are either C sources or C source templates.
# Their comments are extracted and processed through aspell using
# a custom dictionary that contains scads of odd identifiers that
# find their way into the comments.
#
# Currently, this target is setup to be "made" in-tree only.
# The output is ephemeral. Redirect it to guide spelling fixups,
# either to correct spelling or add words to tool/custom.txt.
#
./custom.rws: ./tool/custom.txt
	@echo 'Updating custom dictionary from tool/custom.txt'
	aspell --lang=en create master ./custom.rws < ./tool/custom.txt
# Note that jimsh does not work here:
# https://github.com/msteveb/jimtcl/issues/319
misspell: ./custom.rws has_tclsh84
	$(TCLSH_CMD) ./tool/spellsift.tcl ./src/*.c ./src/*.h ./src/*.in

#
# clean/distclean are mostly defined in main.mk. In this makefile we
# perform cleanup known to be relevant to (only) the autosetup-driven
# build.
#
#clean-autosetup:
#	-if [ -f ext/wasm/GNUmakefile ]; then \
#		gmake --no-print-directory --ignore-errors -C ext/wasm clean; \
#	fi >/dev/null 2>&1; true
#clean: clean-autosetup

distclean-autosetup:	clean
	rm -f sqlite_cfg.h config.log config.status config.defines.* Makefile sqlite3.pc
	rm -f $(TOP)/tool/emcc.sh
	rm -f libsqlite3*$(T.dll)
	rm -f jimsh0*
distclean: distclean-autosetup

#
# tool/version-info: a utility for emitting sqlite3 version info
# in various forms.
#
version-info$(T.exe): $(TOP)/tool/version-info.c Makefile sqlite3.h
	$(T.link) $(ST_OPT) -o $@ $(TOP)/tool/version-info.c

IS_CROSS_COMPILING = 0
include $(TOP)/main.mk
