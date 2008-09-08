## $Id$
## Process this file with automake to produce Makefile.in

DEFAULT_INCLUDES= -I$(top_srcdir)/include -I$(top_builddir)

AM_CFLAGS = -Wstrict-prototypes -Wall -Werror

noinst_LTLIBRARIES = libcga.la

libcga_la_SOURCES = cga.c hba.c cga_dbg.c cga_keyutils.c cga_mt.c mpadd.c \
	cga_local.h

check_PROGRAMS = hba_test

hba_test_SOURCES = hba_test.c cga.c cga_keyutils.c hba.c cga_dbg.c cga_mt.c
hba_test_LDADD = ../liblog/liblog.la ../libutils/libutils.la
hba_test_CFLAGS = $(AM_CFLAGS) -DAPPLOG_DEBUG

TESTS = $(check_PROGRAMS)
