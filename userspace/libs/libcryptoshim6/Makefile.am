#-gstabs is for having debug information useable by gdb

AM_CFLAGS = -Wstrict-prototypes -Wall -Werror
AM_YFLAGS = -d -p params_
AM_LFLAGS = -Pparams_
LEX_OUTPUT_ROOT=lex.params_

DEFAULT_INCLUDES= -I$(top_srcdir)/include -I$(top_builddir)

noinst_LTLIBRARIES = libcryptoshim6.la liblex.la

#Convenience library for being able to compile params_lex.c with different 
#CFLAGS (because gcc 4.3.2 gives warnings for flex 2.5.35 generated files)
liblex_la_CFLAGS =
liblex_la_SOURCES = params_lex.l


libcryptoshim6_la_SOURCES = cga.c hba.c \
			cga_params.c \
			sigmeth.c \
			sig_RSASSA-PKCS1-v1_5.c sig_RSASSA-PKCS1-v1_5.h \
			openssl.c \
			params_gram.y
libcryptoshim6_la_LIBADD = ../libcga/libcga.la ../libhashtbl/libhashtbl.la \
			./liblex.la
