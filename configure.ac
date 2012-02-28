AC_PREREQ(2.59)
AC_INIT([VOMS Oracle plugin], [3.1.15])
AC_PREFIX_DEFAULT("/")
AC_CONFIG_AUX_DIR([./aux])
AC_CONFIG_SRCDIR([src/oraclewrap.cc])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

# Notices.
AC_COPYRIGHT([Copyright (c) 2004-2012 Istituto Nazionale di Fisica Nucleare
See LICENCE file for details
])

#Environment.
WORKDIR=`pwd`
AC_SUBST(WORKDIR)

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CXX
AC_PROG_CXXCPP
AC_PROG_LIBTOOL

# Checks for libraries

# check for oracle
AC_ORACLE_INSTANTCLIENT

VOMS_CERTS
DEBUG
VOMS_SOCKLEN_T

AC_CHECK_FUNCS(sigaction)

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE

AM_CONFIG_HEADER([src/autogen/config.h])
AC_CONFIG_FILES([Makefile
                 config/Makefile
                 src/Makefile
                 spec/voms-oracle-plugin.spec])
AC_OUTPUT
