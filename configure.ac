
AC_PREREQ(2.59)
AC_INIT([Glite Security VOMS Oracle], [3.0.1])
AC_CONFIG_AUX_DIR([./project])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/oraclewrap.cc])

AM_MAINTAINER_MODE

# Notices.
AC_COPYRIGHT([Copyright (c) 2004 The EU EGEE Project
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

# Dependencies checks
AC_ENABLE_GLITE # embed AC_GLITE

# check for oracle
AC_ORACLE_INSTANTCLIENT

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
                 src/Makefile])

AC_OUTPUT
