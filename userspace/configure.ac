AC_INIT([LinShim6],[0.9-th],[sebastien.barre@uclouvain.be])
AM_INIT_AUTOMAKE(LinShim6,0.9-th)
AC_GNU_SOURCE
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AC_PROG_LEX
AC_PROG_YACC
AC_PROG_LIBTOOL
AC_PROG_SED

AM_PROG_CC_C_O

AC_C_INLINE
AC_C_BIGENDIAN(
	[AC_DEFINE([__BIG_ENDIAN_BITFIELD],[1],[Byte order is big endian])],
	[AC_DEFINE([__LITTLE_ENDIAN_BITFIELD],[1],
			[Byte order is little endian])]
	)

AC_MSG_NOTICE([*** checking for Shim6 support in kernel headers])
AC_CHECK_DECLS([SHIM6_TYPE_I1],,
        [AC_MSG_ERROR([kernel headers do not support Shim6.

*** If working Linux kernel headers are not in the default include path,
*** please use CPPFLAGS variable to specify where they can be found 
*** (e.g. CPPFLAGS="-isystem /usr/src/linux/include")
])], [#include <linux/shim6.h>])

AC_CHECK_HEADERS([linux/xfrm.h],[],
	AC_MSG_ERROR([xfrm header not found in linux include directory.]))

AC_CHECK_DECLS([XFRM_MODE_SHIM6],,
        [AC_MSG_ERROR([kernel headers seem supporting a different LinShim6 version. Please first update your kernel sources.

*** If working Linux kernel headers are not in the default include path,
*** please use CPPFLAGS variable to specify where they can be found 
*** (e.g. CPPFLAGS="-isystem /usr/src/linux/include")
])], [#include <sys/types.h>
      #include <linux/xfrm.h>])


AC_CHECK_HEADERS([readline/readline.h],[],
	AC_MSG_ERROR([readline/readline.h header not found]))

AC_CHECK_HEADERS([readline/history.h],[],
	AC_MSG_ERROR([readline/history.h header not found]))

AC_MSG_NOTICE([*** checking for additional external libraries])

AC_CHECK_LIB(pthread,pthread_create,[],
	AC_MSG_ERROR([POSIX thread library required but not found.]))

AC_CHECK_LIB(ncurses,tgetnum,[],
	AC_MSG_ERROR([GNU ncurses library required but not found.]))

AC_CHECK_LIB(readline,readline,[],
	AC_MSG_ERROR([GNU readline library required but not found.]))

AC_CHECK_LIB(netlink, rtnl_talk)
AM_CONDITIONAL(LOCAL_NETLINK, test x$ac_cv_lib_netlink_rtnl_talk = xno)
AC_CHECK_LIB(crypto,SHA1,[],
	AC_MSG_ERROR([OpenSSL crypto library required but not found.]))
AC_CHECK_FUNC([clock_gettime])
if test $ac_cv_func_clock_gettime = no; then
   AC_CHECK_LIB(rt, clock_gettime,,
		[AC_MSG_ERROR([librt required but not found])])
fi

AC_ARG_ENABLE(debug,
	AC_HELP_STRING([--enable-debug],[enable debug messages and asserts 
	(default yes)]),
	[ac_enable_debug=$enableval], [ac_enable_debug=yes])
if test x$ac_enable_debug = xyes; then
   AC_DEFINE([SHIM6_DEBUG], [1], [Enable printing of debug messages])
   AC_DEFINE([DEBUGGING], [1],[Enable asserts and pthread debug messages])
   AC_DEFINE([APPLOG_DEBUG],[1],Enable the debug system for the parts of the 
   code taken from applog (radvd/DoCoMo))
   AC_SUBST(CPPFLAGS,["$CPPFLAGS -O0"])
   AC_SUBST(CFLAGS,[-ggdb])
else
   AC_DEFINE([MIP6_NDEBUG], [1], [Disable MIP6-related debugging])
fi

AC_ARG_ENABLE(log_expl_time,
	AC_HELP_STRING([--enable-log-expl-time],[enable logging of exploration 
	times inside /etc/shim6/expl.log (default no)]),
	[ac_enable_log_expl_time=$enableval],[ac_enable_log_expl_time=no])
if test x$ac_enable_log_expl_time = xyes; then
   AC_DEFINE([LOG_EXPL_TIME],[1],[enable logging of exploration times inside 
   /etc/shim6/expl.log])
fi

AC_ARG_ENABLE(log-rcv-i2-time,
	AC_HELP_STRING([--enable-log-rcv-i2-time],[enable logging of i2 reception times inside /etc/shim6/i2.log (default no)]),
	[ac_enable_log_rcv_i2_time=$enableval],[ac_enable_log_rcv_i2_time=no])
if test x$ac_enable_log_rcv_i2_time = xyes; then
   AC_DEFINE([LOG_RCV_I2_TIME],[1],[enable logging of i2 reception times inside /etc/shim6/i2.log])
fi

AC_ARG_ENABLE(idips,
	AC_HELP_STRING([--enable-idips],[enable use of an idips server. You 
	must first install the IDIPS software if you want this option to work 
	properly.(default no)]),
	[ac_enable_idips=$enableval],[ac_enable_idips=no])
if test x$ac_enable_idips = xyes; then
   AC_CHECK_HEADERS([idips/client.h],[],	
	AC_MSG_ERROR([idips/client.h header not found]))
   AC_DEFINE([IDIPS],[1],[enable use with an IDIPS server])
fi

AC_ARG_ENABLE(cgaconsole,
	AC_HELP_STRING([--enable-cgaconsole],[enable the console for the cgatool program (default yes)]),
	[ac_enable_cgaconsole=$enableval],[ac_enable_cgaconsole=yes])
if test x$ac_enable_cgaconsole = xyes; then
   AC_DEFINE([USE_CONSOLE],[1],[enable console for prog cgatool])
fi

AC_ARG_ENABLE(dropconfig,
	AC_HELP_STRING([--disable-dropconfig],[By default the old config files
	are replaced. If this option is set, new config files will be available
	in the distribution/config directory, but will not be installed.
	Note that if you use that option, you should at least check for
	consistency between your version and that of the package, especially
	in case of version change of LinShim6. Finally, note that the keys/der
	are never overwritten. If a key/der is found, it is not regenerated.
	(default no)]),
	[ac_disable_dropconfig=$disableval],
	[ac_disable_dropconfig=no])
AM_CONDITIONAL([DROPCONFIG], [test x$ac_disable_dropconfig = xno])

AC_ARG_ENABLE(installtools,
	AC_HELP_STRING([--enable-installtools],[Installs the tools provided 
	with the LinShim6 package. This is absolutely not needed, unless you 
	want to make quantitative measurements of LinShim6 (default no)]),
	[ac_enable_installtools=$enableval],
	[ac_enable_installtools=no])
AM_CONDITIONAL([INSTALLTOOLS], [test x$ac_enable_installtools = xyes])

AC_ARG_ENABLE(cgacheck,
	AC_HELP_STRING([--disable-cgacheck],[disable the CGA check, so that 
	context may also be created with unsecured locator sets from the 
	peer. You should NOT use that option, unless you want to make
	interoperability tests with other implementations that do not
	support CGA yet (default no)]),
	[ac_enable_cgacheck=$enableval],[ac_enable_cgacheck=yes])
if test x$ac_enable_cgacheck = xno; then
   AC_DEFINE([NO_CGA_CHECK],[1],[disable cga check])
fi

#Where to find the config scripts
confdirx=`eval echo $sysconfdir`
case $confdirx in
     NONE/*) confdirx=`echo $confdirx | sed "s~NONE~$ac_default_prefix~"` ;;
esac
AC_DEFINE_UNQUOTED([CONFIG_DIR],"$confdirx",
	[Directory for configuration files])

#local state dir
localstatedirx=`eval echo $localstatedir`
case $localstatedirx in
     NONE/*) localstatedirx=`echo $localstatedirx | sed "s~NONE~~"` ;;
esac
AC_DEFINE_UNQUOTED([LOCALSTATE_DIR],"$localstatedirx",[Local state dir])

AC_CONFIG_FILES([
	Makefile
	libs/Makefile
	libs/libnetlink/Makefile
	libs/libcga/Makefile
	libs/libhashtbl/Makefile
	libs/liblog/Makefile
	libs/libconfig/Makefile
	libs/libappconsole/Makefile
	libs/libthrpool/Makefile
	libs/libtimer/Makefile
	libs/libprioq/Makefile
	libs/libcryptoshim6/Makefile
	libs/libutils/Makefile
	src/Makefile
	cgatool/Makefile
	cgad/Makefile
	config/Makefile
	shim6c/Makefile
])
AC_OUTPUT
