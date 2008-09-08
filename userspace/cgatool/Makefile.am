AM_CFLAGS = -Wstrict-prototypes -Wall -Werror
AM_CPPFLAGS = -D__USE_GNU -I ../include
DEFAULT_INCLUDES = -I$(top_srcdir)/include -I$(top_builddir)

bin_PROGRAMS = 		cgatool

cgatool_SOURCES = 	cgatool.c

cgatool_LDADD = 	../libs/libcga/libcga.la \
			../libs/liblog/liblog.la \
			../libs/libconfig/libconfig.la \
			../libs/libappconsole/libappconsole.la \
			../libs/libhashtbl/libhashtbl.la

noinst_HEADERS =        ../include/libconfig.h

dist_check_SCRIPTS = test_cga.sh
EXTRA_DIST = rfc_example.params
TESTS = test_cga.sh
