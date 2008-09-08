#-gstabs is for having debug information useable by gdb

AM_CFLAGS = -Wstrict-prototypes -Wall -Werror
AM_CPPFLAGS = -D__USE_GNU -DSHIM6_SRC
AM_LDFLAGS = -lpthread -lrt -lcrypto -lreadline -lutil
DEFAULT_INCLUDES = -I$(top_srcdir)/include -I$(top_builddir)
AM_YFLAGS = -d -p params_
AM_LFLAGS = -Pparams_
LEX_OUTPUT_ROOT=lex.params_

bin_PROGRAMS = shim6d


shim6d_SOURCES	 = 	main.c reapd.c \
			shim6_netlink.c shim6d.c \
			xfrm.c xfrm.h shim6_rawsocket.c \
			shim6_rawsocket.h \
			info_server.c info_server.h pipe.c pipe.h \
			opt.c opt.h tqueue.c \
			idips.c idips.h shim6_local.h random.c random.h \
			testparams.h

shim6d_LDADD = ../libs/libcga/libcga.la \
		../libs/liblog/liblog.la \
		../libs/libcryptoshim6/libcryptoshim6.la \
		../libs/libutils/libutils.la ../libs/libhashtbl/libhashtbl.la

if INSTALLTOOLS
bin_PROGRAMS += shim6eval
shim6eval_SOURCES = shim6eval.c reapd.c \
			shim6_netlink.c shim6d.c \
			xfrm.c xfrm.h shim6_rawsocket.c \
			shim6_rawsocket.h \
			info_server.c info_server.h pipe.c pipe.h \
			opt.c opt.h tqueue.c \
			idips.c idips.h shim6_local.h random.c random.h \
			testparams.h

shim6eval_LDADD = ../libs/libcga/libcga.la \
		../libs/liblog/liblog.la \
		../libs/libcryptoshim6/libcryptoshim6.la \
		../libs/libutils/libutils.la ../libs/libhashtbl/libhashtbl.la

shim6eval_CPPFLAGS = -DSHIM6EVAL -D__USE_GNU -DSHIM6_SRC

endif


if LOCAL_NETLINK
shim6d_LDADD += ../libs/libnetlink/libnetlink.la
if INSTALLTOOLS
shim6eval_LDADD+=../libs/libnetlink/libnetlink.la
endif
endif

noinst_HEADERS = $(top_srcdir)/include/*.h  \
		$(top_srcdir)/include/cryptoshim6/*.h \
		$(top_srcdir)/include/netinet/*.h \
		$(top_srcdir)/include/shim6/*.h \
		$(top_srcdir)/include/utils/*.h
