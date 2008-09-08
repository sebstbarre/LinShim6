#-gstabs is for having debug information useable by gdb

AM_CFLAGS = -Wstrict-prototypes -Wall -Werror
AM_CPPFLAGS = -D__USE_GNU -I ../include
AM_LDFLAGS = -lpthread -lrt -lcrypto
DEFAULT_INCLUDES = -I$(top_srcdir)/include -I$(top_builddir)
AM_YFLAGS = -d -p params_
AM_LFLAGS = -Pparams_
LEX_OUTPUT_ROOT=lex.params_

bin_PROGRAMS = cgad
cgad_SOURCES = cgad.c net.c os_defines.h dbg.h cgad_local.h addr.c \
		cgad_linux.c os_specific.h ra.c proto.c config.c \
		cgad_config.h dbg.c addr_linux.c rand.c opt.c \
		cgad_proto.h cgad_linux.h


cgad_LDADD = ../libs/libcga/libcga.la ../libs/libtimer/libtimer.la \
		../libs/liblog/liblog.la ../libs/libthrpool/libthrpool.la \
		../libs/libcryptoshim6/libcryptoshim6.la \
		../libs/libconfig/libconfig.la \
		../libs/libhashtbl/libhashtbl.la \
		../libs/libappconsole/libappconsole.la \
		../libs/libprioq/libprioq.la ../libs/libutils/libutils.la \
		../libs/libutils/libutils.la

if LOCAL_NETLINK
cgad_LDADD += ../libs/libnetlink/libnetlink.la
endif

noinst_HEADERS = ../include/netinet/in.h ../include/list.h \
		../include/hashtbl.h ../include/cga.h \
		../include/applog.h ../include/cga_keyutils.h \
		../include/libnetlink.h ../include/sbuff.h
