
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([Glite Security VOMS Oracle], [1.0.0])
AC_CONFIG_AUX_DIR([./project])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/oraclewrap.cc])

#Environment.
WORKDIR=`pwd`
AC_SUBST(WORKDIR)

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CXX
AC_PROG_CXXCPP
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([ociei], [OCIEnvCreate])
AC_CHECK_LIB([occi], [CreateEnvironment])
ORACLE_CHECKS

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE

AC_GLITE

AM_CONFIG_HEADER([src/autogen/config.h])
AC_CONFIG_FILES([Makefile
		 config/Makefile
                 src/Makefile])

AC_OUTPUT
