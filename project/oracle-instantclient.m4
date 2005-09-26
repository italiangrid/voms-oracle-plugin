dnl AC_ORACLE_INSTANTCLIENT([ ])
dnl define ORACLE_CFLAGS , ORACLE_OCI_LIBS, ORACLE_STATIC_OCCI_LIBS and ORACLE_OCCI_LIBS
dnl
AC_DEFUN([AC_ORACLE_INSTANTCLIENT],
[
	# Set Oracle InstantClient Properties
	AC_ARG_WITH(oracle_prefix,
		[  --with-oracle-prefix=PFX     prefix where Oracle Client is installed. (/usr/lib/oracle)],
		[],
	        with_oracle_prefix=${ORACLE_PATH:-/usr/lib/oracle})
	        
	AC_ARG_WITH(oracle_version,
		[  --with-oracle-version=PFX     Oracle Client version. (10.1.0.3)],
		[],
	        with_oracle_version=${ORACLE_VERSION:-10.1.0.3})

	ORACLE_PATH="$with_oracle_prefix"
	ORACLE_VERSION="$with_oracle_version"
	ORACLE_CFLAGS="-I$with_oracle_prefix/include/oracle/$with_oracle_version/client"
	ac_oracle_ldlib="-L$with_oracle_prefix/lib//oracle/$with_oracle_version/client/lib"
	ORACLE_OCI_LIBS="$ac_oracle_ldlib -lclntsh -lnnz10 -lociei"
	ORACLE_STATIC_OCCI_LIBS="$ac_oracle_ldlib -lclntsh -lnnz10 -lociei -locci10"
	ORACLE_OCCI_LIBS="$ac_oracle_ldlib -lclntsh -lnnz10 -lociei -locci"
	    
	AC_SUBST(ORACLE_PATH)
	AC_SUBST(ORACLE_VERSION)
	AC_SUBST(ORACLE_CFLAGS)
	AC_SUBST(ORACLE_OCI_LIBS)
	AC_SUBST(ORACLE_STATIC_OCCI_LIBS)
	AC_SUBST(ORACLE_OCCI_LIBS)
])
