
AC_DEFUN([ORACLE_CHECKS],
[AC_MSG_CHECKING([for Oracle libdir])
AC_ARG_WITH(oracle-libdir,
		[ --with-oracle-libdir=<dir> Default is $ORACLE_HOME/lib],
		oracle_libdir="$withval", oracle_libdir="$ORACLE_HOME/lib")
if test -d "$oracle_libdir"; then
   AC_MSG_RESULT([found $oracle_libdir])
   LDFLAGS="$LDFLAGS -L$oracle_libdir"
   LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$oracle_libdir"
else
   AC_MSG_ERROR([no such directory $oracle_libdir])
fi

AC_MSG_CHECKING([for Oracle incdir])
AC_ARG_WITH(oracle-incdir,
	[ --with-oracle-incdir=<dir> Default is $ORACLE_HOME/rdbms/public],
	oracle_incdir="$withval", oracle_incdir="$ORACLE_HOME/rdbms/public")
if test -d "$oracle_incdir"; then
   AC_MSG_RESULT([found $oracle_incdir])
   CPPFLAGS="$CPPFLAGS -I$oracle_incdir"
else
   AC_MSG_ERROR([no such directory $oracle_incdir])
fi
AC_LANG_SAVE
AC_LANG_CPLUSPLUS
AC_CHECK_HEADERS(occi.h)
AC_LANG_RESTORE]
)
