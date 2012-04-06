bin_PROGRAMS = middleman

middleman_SOURCES = middleman.cc ociwrap.cpp ociwrap.hpp
middleman_CPPFLAGS = $(ORACLE_CFLAGS)
middleman_LDADD = $(ORACLE_OCI_LIBS) -lpthread -lcrypto

lib_LTLIBRARIES = libvomsoracle.la

libvomsoracle_la_SOURCES = oraclewrap.cc oraclewrap.h dbwrap.h
libvomsoracle_la_LIBADD = $(ORACLE_OCCI_LIBS)
libvomsoracle_la_LDFLAGS = -module -avoid-version -no-undefined

AM_CPPFLAGS = $(ORACLE_CFLAGS)
