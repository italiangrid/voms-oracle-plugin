
AC_DEFUN([DEBUG],
[
  AC_ARG_WITH(debug,
	  [ --with-debug Compiles without optimizations and with debug activated],
	deb="dbg", deb="")
if ! test "x$deb" = "x" ; then
   CFLAGS="-g -O0"
   CXXFLAGS="-g -O0"
fi

  AC_ARG_WITH(warnings,
	  [ --with-warnings Compiles with maximum warnings],
	wrn="wrn",
	wrn="")
if ! test "x$wrn" = "x" ; then
   CFLAGS="-O -Wall -W"
   CXXFLAGS="-O -Wall -w"
fi
])

# SOCKLEN_T TESTING
# -----------------
AC_DEFUN([VOMS_SOCKLEN_T],
[
  AC_MSG_CHECKING([for (sane) socklen_t])
    AC_TRY_COMPILE(
      [
        #include <sys/types.h> 
        #include <sys/socket.h>
      ],
      [
        socklen_t addrlen = (socklen_t)5;
        (void)getsockname(0, NULL, &addrlen); 
        return 0;
      ],
      [ac_have_socklen_t="yes"],
      [ac_have_socklen_t="no"]
    )
      
    if test "x$ac_have_socklen_t" = "xyes" ; then
      AC_DEFINE(HAVE_SOCKLEN_T, 1, [Define to 1 if you have the socklen_t type])
    fi

    AC_MSG_RESULT([$ac_have_socklen_t])
])

# AC_ENABLE_GLITE switch for glite
# -------------------------------------------------------
AC_DEFUN([AC_ENABLE_GLITE],
[
    AC_ARG_ENABLE(glite,
        [  --enable-glite     enable gLite  ],
        [ac_enable_glite="yes"],
        [ac_enable_glite="no"])

    AM_CONDITIONAL(ENABLE_GLITE, test x$ac_enable_glite = xyes)

    if test "x$ac_enable_glite" = "xno"; then
        DISTTAR=$WORKDIR
        AC_SUBST(DISTTAR)
    else
        AC_GLITE
    fi
])
