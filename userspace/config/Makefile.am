if DROPCONFIG
nobase_sysconf_DATA = cgad.conf cgad/params.conf 
else
noinst_DATA = cgad.conf cgad/params.conf
endif

dist_bin_SCRIPTS = disable_autoconf

EXTRA_DIST= gen_configs.sh

gen_configs = $(top_srcdir)/config/gen_configs.sh

cgaconfdir=$(DESTDIR)$(sysconfdir)

cgad.conf: 
	$(gen_configs) "cgadconf" $(cgaconfdir)

cgad/params.conf:
	$(gen_configs) "paramsconf" $(cgaconfdir)

clean-local:
	rm -rf cgad cgad.conf

if DROPCONFIG
install-data-hook:
	$(gen_configs) "install" $(cgaconfdir)
endif

uninstall-hook:
	rm -rf $(cgaconfdir)/cgad
