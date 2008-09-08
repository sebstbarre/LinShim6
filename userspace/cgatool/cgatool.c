/*
 * Copyright © 2006, DoCoMo Communications Laboratories USA, Inc.,
 *   the DoCoMo SEND Project
 *
 * Modified by Sébastien Barré for LinShim6 - sebastien.barre@uclouvain.be
 * Feb 2008
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of DoCoMo Communications Laboratories USA, Inc., its
 *    parents, affiliates, subsidiaries, theDoCoMo SEND Project nor the names
 *    of the Project's contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL DOCOMO COMMUNICATIONS LABORATORIES USA,
 *  INC., ITS PARENTS, AFFILIATES, SUBSIDIARIES, THE PROJECT OR THE PROJECT'S
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <config.h>
#include <applog.h>
#include <libconfig.h>

#include <cga.h>
#include <cga_keyutils.h>

static cga_ctx_t *cga;
static int hba = 0;


#ifndef	ARR_SZ
#define	ARR_SZ(a) (sizeof (a) / sizeof (*a))
#endif

static void
str2hex(char *str, uint8_t *a, int *len, char fs)
{
	int i, j;
	char *p, *pp;

	/* count the number of ':'s in the L2 address */
	for (i = 0, p = str; (p = strchr(p, fs)) != NULL; i++, p++) {
		/* skip duplicate seperators */
		while (p && *p == fs) p++;
	}

	i++;
	if (i > *len) {
		printf("modifier too long\n");
		return;
	}

	p = str;
	for (j = 0; j < i; j++) {
		pp = p;
		p = strchr(p, fs);
		if (p) {
			*p++ = 0;
			/* skip duplicate seperators */
			while (*p == fs) p++;
		}

		a[j] = strtol(pp, NULL, 16);
	}

	*len = i;
}

static int
do_set_sec(const char *p)
{
	int sec = atoi(p);

	return (cga_set_sec(cga, sec));
}

static int
do_set_prefix(const char *p)
{
	int r;
	struct in6_addr a[1];

	r = inet_pton(AF_INET6, p, a);
	if (r < 0) {
		printf("set prefix: inet_pton failed: %s\n", strerror(errno));
		return (-1);
	} else if (r == 0) {
		printf("set prefix: inet_pton: not a valid IPv6 address\n");
		return (-1);
	}
	cga_set_prefix(cga, a);

	return (0);
}

static int 
do_set_prefixes(const char** p, int n)
{
	int r,i;
	uint64_t *a=malloc(n*sizeof(*a));
	struct in6_addr tmp_addr;
	struct hba_set* hs;

	if (!a) {
		APPLOG_NOMEM();
		return EXIT_FAILURE;
	}
	
	for (i=0;i<n;i++) {
		r = inet_pton(AF_INET6,p[i],&tmp_addr);
		memcpy(&a[i],&tmp_addr,sizeof(a[i]));
		if (r < 0) {
			printf("set prefix: inet_pton failed: %s\n", 
			       strerror(errno));
			return (-1);
		} else if (r == 0) {
			printf("set prefix: inet_pton: not a valid IPv6"
			       " address\n");
			return (-1);
		}		
	}
	
	hs=new_hbaset_pfx("cgatool",a,n);
	if (hba_set_prefixes(cga, hs)<0) return (-1);
	if (cga->der && hba_autogen_mpe(cga)<0) {
		printf("%s: hba_autogen_mpe failed\n",
		       __FUNCTION__);
		return -1;
	}

	return 0;
}

static int
do_set_address(const char *p)
{
	int r;
	struct in6_addr a[1];

	r = inet_pton(AF_INET6, p, a);
	if (r < 0) {
		printf("set addr: inet_pton failed: %s\n", strerror(errno));
		return (-1);
	} else if (r == 0) {
		printf("set addr: inet_pton: not a valid IPv6 address\n");
		return (-1);
	}
	cga_set_addr(cga, a);

	return (0);
}

static int
do_load_key(const char *p)
{

	return (cga_load_key(cga, p));
}

static int
do_load_cert(const char *f)
{
	return (cga_load_cert(cga, f));
}

static void
do_set_mod(char *p)
{
	int len = CGA_MODLEN;
	uint8_t mod[CGA_MODLEN];

	memset(mod, 0, sizeof (mod));
	str2hex(p, mod, &len, ' ');
	cga_set_modifier(cga, mod);
}

static int
do_set_coll(const char *p)
{
	return (cga_set_col(cga, atoi(p)));
}

static void
rsa_cb(int p, int n, void *a)
{
#ifdef	I_WANT_SOMETHING_TO_WATCH_WHILE_WAITING_FOR_MY_NEW_KEY
	char c = 'B';

	if (p == 0) c = '|';
	if (p == 1) c = '/';
	if (p == 2) c = '-';
	if (p == 3) c = '\\';
	fprintf(stderr, "\r%c", c);
#endif
}

static int
do_gen_rsa(const char *bstr, const char *kfile)
{
	int bits = atoi(bstr);
	EVP_PKEY *pk;
	RSA *rsa;
	FILE *fp;

	if ((pk = EVP_PKEY_new()) == NULL) {
		fprintf(stderr, "EVP_PKEY_new() failed\n");
		return (-1);
	}

	rsa = RSA_generate_key(bits, RSA_F4, rsa_cb, NULL);
	if (EVP_PKEY_assign_RSA(pk, rsa) == 0) {
		fprintf(stderr, "EVP_PKEY_assign_RSA() failed\n");
		RSA_free(rsa);
		EVP_PKEY_free(pk);
		return (-1);
	}

	if ((fp = fopen(kfile, "w")) == NULL) {
		fprintf(stderr, "Could not open file %s for writing: %s\n",
			kfile, strerror(errno));
		RSA_free(rsa);
		EVP_PKEY_free(pk);
		return (-1);
	}
	if (!PEM_write_PrivateKey(fp, pk, NULL, NULL, 0, NULL, NULL)) {
		fprintf(stderr, "PEM_write_PrivateKey() failed\n");
		RSA_free(rsa);
		EVP_PKEY_free(pk);
		return (-1);
	}
	fclose(fp);

	return (cga_set_key(cga, pk));
}

static int
do_gen_pseudokey(void)
{
	u_int8_t pseudokey[48];
	applog(LOG_DEBUG, "%s: Generating HBA pseudo-key", __FUNCTION__);
	if (get_rand_bytes(pseudokey, sizeof(pseudokey))<0)
		return -1;
	if (hba_set_pseudo(cga,pseudokey,sizeof(pseudokey))<0)
		return -1;
	return 0;
}

static int
do_set_thrcnt(const char *p)
{
	int tc;

	tc = atoi(p);
	if (tc <= 0) {
		printf("Invalid thread count\n");
		return (-1);
	}
	cga->thrcnt = tc;

	return (0);
}

static int
do_set_batchsize(const char *p)
{
	int bs;

	bs = atoi(p);
	if (bs <= 0) {
		printf("Invalid batch size\n");
		return (-1);
	}
	cga->batchsize = bs;

	return (0);
}

static int
do_readder(const char *p)
{
	struct stat sb[1];
	FILE *fp;
	uint8_t *der;
	int dlen;

	if (stat(p, sb) < 0) {
		printf("Could not stat file: %s\n", strerror(errno));
		return (-1);
	}

	if ((fp = fopen(p, "r")) == NULL) {
		printf("Could not open file: %s\n", strerror(errno));
		return (-1);
	}

	if ((der = malloc(sb->st_size)) == NULL) {
		printf("No memory\n");
		fclose(fp);
		return (-1);
	}

	fread(der, 1, sb->st_size, fp);
	fclose(fp);
	dlen = sb->st_size;

	if (cga_set_der(cga, der, dlen) < 0) {
		printf("Invalid params\n");
		free(cga->der);
		cga->der = NULL;
		return (-1);
	}

	return (0);
}

static int
do_writeder(const char *f)
{
	FILE *fp;

	if (cga->der == NULL) {
		printf("der not set\n");
		return (-1);
	}
	if ((fp = fopen(f, "w")) == NULL) {
		printf("Could not open file: %s\n", strerror(errno));
		return (-1);
	}

	fwrite(cga->der, 1, cga->derlen, fp);
	fclose(fp);

	return (0);
}

static void
gen_sighandler(int sig)
{
	cga_gen_cancel();
}

static int
do_gen(char *b)
{
	int r = -1;
	char abuf[INET6_ADDRSTRLEN];
	int i;
	struct hba_set* hs=cga->hba_data;

	if (!cga->key_set) {
		printf("generate: key is not set\n");
	}

	if (hba) cga->is_hba_ctx=1;

	if ((!hba && !cga->prefix_set) || (hba && !cga->prefixes_set)) {
		printf("generate: prefix is not set\n");
	}

	if (signal(SIGINT, gen_sighandler) < 0) {
		perror("signal(SIGINT)");
		return (-1);
	}

	if ((!hba && cga_generate(cga) != 0) ||
	    (hba && hba_generate(cga))) {
		printf("failed\n");
		goto done;
	}
	if (hs) free(hs); /*Not used anymore*/
	if (!hba) printf("%s\n",
			 inet_ntop(AF_INET6, &cga->addr, abuf, sizeof (abuf)));
	else for (i=0;i<cga->hba_data->length;i++)
		     printf("%s\n",inet_ntop(AF_INET6, 
					     &cga->hba_data->set_addr[i],abuf,
					     sizeof(abuf)));
	r = 0;
	
done:
	signal(SIGINT, SIG_DFL);
	return (r);
}

static int
do_ver(char *b)
{
	if (!cga->der_set) {
		printf("verify: DER-encoded paramaters are not set\n");
	}
	if (!cga->addr_set) {
		printf("verify: address is not set\n");
	}

	if (cga_verify(cga) != 0) {
		printf("failed\n");
		return (-1);
	}

	return (0);
}

static int
read_config(const char *p)
{
	const char *v;
	char *x;
	int rv;

	if ((rv = config_init(p)) != 0) {
		printf("config_init failed: %s\n", strerror(errno));
		return (-1);
	}

#define	CHECK_ERR(__f, __v) if (__f(__v) < 0) rv = -1;
	if ((v = config_get("certfile", NULL)) != NULL) {
		CHECK_ERR(do_load_cert, v);
	}
	if ((v = config_get("derfile", NULL)) != NULL) {
		CHECK_ERR(do_readder, v);
	}
	if ((v = config_get("keyfile", NULL)) != NULL) {
		CHECK_ERR(do_load_key, v);
	}
	if ((v = config_get("address", NULL)) != NULL) {
		CHECK_ERR(do_set_address, v);
	}
	if ((v = config_get("prefix", NULL)) != NULL) {
		CHECK_ERR(do_set_prefix, v);
	}
	if ((v = config_get("cga_sec", NULL)) != NULL) {
		CHECK_ERR(do_set_sec, v);
	}
	if ((v = config_get("modifier", NULL)) != NULL) {
		if ((x = strdup(v)) != NULL) {
			do_set_mod(x);
			free(x);
		} else {
			fprintf(stderr, "no memory\n");
			return (-1);
		}
	}
	if ((v = config_get("collisions", NULL)) != NULL) {
		CHECK_ERR(do_set_coll, v);
	}
	if ((v = config_get("batchsize", NULL)) != NULL) {
		CHECK_ERR(do_set_batchsize, v);
	}
	if ((v = config_get("thrcnt", NULL)) != NULL) {
		CHECK_ERR(do_set_thrcnt, v);
	}

	return (rv);
}

static pthread_mutex_t *lock_cs;
static int numlocks;

static void
ssl_locking_callback(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(lock_cs + n);
	} else {
		pthread_mutex_unlock(lock_cs + n);
	}
}

static int
ssl_thread_init(void)
{
	int i;

	numlocks = CRYPTO_num_locks();
	if ((lock_cs = malloc(numlocks * sizeof (*lock_cs))) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (-1);
	}

	for (i = 0; i < numlocks; i++) {
		pthread_mutex_init(lock_cs + i, NULL);
	}

	CRYPTO_set_locking_callback(ssl_locking_callback);

	return (0);
}

static void
ssl_thread_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);

	for (i = 0; i < numlocks; i++) {
		pthread_mutex_destroy(lock_cs + i);
	}

	free(lock_cs);
}

static void
free_ctx(void)
{
	cga_free_ctx(cga);
}


#ifdef	USE_CONSOLE
#include <appconsole.h>
static void
hexdump(uint8_t *b, int len, char *indent)
{
	int i;

	if (indent) printf(indent);
	for (i = 0; i < len; i++) {
		int v = b[i] & 0xff;
		printf("%.2x ", v);

		if (((i + 1) % 16) == 0) {
			printf("\n");
			if (indent) printf(indent);
		} else if (((i + 1) % 8) == 0) {
			printf(" ");
		}
	}
}

static void
do_show(char *b)
{
	char abuf[INET6_ADDRSTRLEN];

	printf("\tprefix: %s\n",
	       inet_ntop(AF_INET6, &cga->prefix, abuf, sizeof (abuf)));
	printf("\tcollisions: %d\n", cga->collisions);
	printf("\tsec: %d\n", (int)cga->sec);
	printf("\tmodifier: ");
	hexdump(cga->modifier, CGA_MODLEN, NULL);
	printf("\n");
	printf("\taddress: %s\n",
	       inet_ntop(AF_INET6, &cga->addr, abuf, sizeof (abuf)));
	if (cga->der) {
		printf("\tparameters:\n");
		hexdump(cga->der, cga->derlen, "\t\t");
		printf("\n");
	} else {
		printf("\tparameters: not set\n");
	}
	if (cga->key) {
		printf("\tpublic key:\n");
		hexdump(cga->key, cga->klen, "\t\t");
		printf("\n");
	} else {
		printf("\tpublic key: not set\n");
	}

	printf("\tbatchsize: %u\n", cga->batchsize);
	printf("\tthread count: %d\n", cga->thrcnt);

#ifdef	APPLOG_DEBUG
	printf("\tdebug: ");
	applog_print_curlevels();
	printf("\n");
#endif
}

static void
set_sec(char *b)
{
	char *p;

	APPCONSOLE_FIRST_ARG(b, p, "parse error: missing sec value\n");

	do_set_sec(p);
}

static void
set_prefix(char *b)
{
	char *p;

	APPCONSOLE_FIRST_ARG(b, p, "parse error: missing prefix\n");

	do_set_prefix(p);
}

static void
set_address(char *b)
{
	char *p;

	APPCONSOLE_FIRST_ARG(b, p, "parse error: missing address\n");

	do_set_address(p);
}

static void
load_key(char *b)
{
	char *p;

	APPCONSOLE_FIRST_ARG(b, p, "parse error: missing key file\n");

	do_load_key(p);
}

static void
load_cert(char *b)
{
	char *p;

	APPCONSOLE_FIRST_ARG(b, p,
	    "parse error: missing certificate file name\n");

	do_load_cert(p);
}

static void
set_mod(char *b)
{
	char *p;

	APPCONSOLE_FIRST_ARG(b, p, "parse error: missing modifier\n");

	do_set_mod(p);
}

static void
use_mod(char *b)
{
	cga->mod_set = 1;
}

static void
clear_mod(char *b)
{
	cga->mod_set = 0;
}

static void
set_coll(char *b)
{
	char *p;

	APPCONSOLE_FIRST_ARG(b, p, "parse error: missing collision count\n");

	do_set_coll(p);
}

static void
gen_rsa(char *b)
{
	char *bits, *kfile;

	APPCONSOLE_FIRST_ARG(b, bits, "parse error: missing bits\n");
	APPCONSOLE_NEXT_ARG(bits, kfile, "parse error: missing keyfile\n");

	do_gen_rsa(bits, kfile);
}

static void
do_thrcnt(char *b)
{
	char *p;

	APPCONSOLE_FIRST_ARG(b, p, "parse error: missing thread count\n");

	do_set_thrcnt(p);
}

static void
do_batchsize(char *b)
{
	char *p;

	APPCONSOLE_FIRST_ARG(b, p, "parse error: missing batch size\n");

	do_set_batchsize(p);
}

static void
do_config(char *b)
{
	char *p;

	APPCONSOLE_FIRST_ARG(b, p, "parse error: missing file name\n");

	read_config(p);
}

static void
writeder(char *b)
{
	char *p;

	APPCONSOLE_FIRST_ARG(b, p, "parse error: missing file name\n");
	do_writeder(p);
}

static void
readder(char *b)
{
	char *p;

	APPCONSOLE_FIRST_ARG(b, p, "parse error: missing file name\n");

	do_readder(p);
}

#ifdef	APPLOG_DEBUG
static void
do_debug_on(char *b)
{
	char *ctx, *lvl;

	APPCONSOLE_FIRST_ARG(b, ctx, "parse error: missing context\n");

	if (strncasecmp(ctx, "all", 3) == 0) {
		applog_addlevel(log_all_on);
		return;
	}

	APPCONSOLE_NEXT_ARG(ctx, lvl, "parse error: missing level\n");

	applog_enable_level(ctx, lvl);
}

static void
do_debug_off(char *b)
{
	char *ctx, *lvl;

	APPCONSOLE_FIRST_ARG(b, ctx, "parse error: missing context\n");

	if (strncasecmp(ctx, "all", 3) == 0) {
		applog_clearlevel(log_all_on);
		return;
	}

	APPCONSOLE_NEXT_ARG(ctx, lvl, "parse error: missing level\n");

	applog_disable_level(ctx, lvl);
}

static void
do_which_levels(char *b)
{
	applog_printlevels();
}

#endif /* APPLOG_DEBUG */

static void
exitcb(void)
{
	exit(0);
}

static int
do_select(int cfd)
{
	fd_set fds[1];

	for (;;) {
		FD_ZERO(fds);
		FD_SET(cfd, fds);

		if (select(cfd + 1, fds, NULL, NULL, NULL) < 0) {
			if (errno == EINTR) {
				continue;
			}
			printf("select(console): %s", strerror(errno));
			return (-1);
		}
		if (FD_ISSET(cfd, fds)) {
#ifdef	USE_READLINE
			console_read_char();
#else
			console_read();
#endif	/* USE_READLINE */
		}
	}

	return (0);
}

static cons_info_t cmds[] = {
	{ "show_ctx", "Show current CGA context", 2, do_show },
	{ "sec", "\tSet sec value", 3, set_sec },
	{ "prefix", "\tSet prefix", 3, set_prefix },
	{ "certfile", "\tLoad certificate", 2, load_cert },
	{ "keyfile", "\tLoad a key from file", 2, load_key },
	{ "rsa", "\tGenerate a RSA keypair", 3, gen_rsa },
	{ "modifier", "Set modifier", 2, set_mod },
	{ "usemod", "\tUse current modifier", 3, use_mod },
	{ "clearmod", "Don't use current modifier", 3, clear_mod },
	{ "collisions", "Set collision count", 3, set_coll },
	{ "generate", "Generate address", 2, (cons_cmd_handler)do_gen },
	{ "address", "\tSet the address", 2, set_address },
	{ "config", "\tLoad params from file", 3, do_config },
	{ "writeder", "Write params to a file", 3, writeder },
	{ "readder", "\tRead params from a file", 3, readder },
	{ "batchsize", "Set batch size", 3, do_batchsize },
	{ "thrcnt", "\tSet thread count", 3, do_thrcnt },
	{ "verify", "\tVerify address", 2, (cons_cmd_handler)do_ver },
#ifdef	APPLOG_DEBUG
	{ "debug_on", "Enable / disable debug", 8, do_debug_on },
	{ "debug_off", "Enable / disable debug", 8, do_debug_off },
	{ "debug_levels", "Show possible debug levels", 8, do_which_levels },
#endif
};
#endif	/* USE_CONSOLE */

static struct option cmd_opts[] = {
	{ "addr", 1, 0, 'a' },
	{ "conffile", 1, 0, 'c' },
	{ "certfile", 1, 0, 'C' },
	{ "debug", 0, 0, 'd' },
	{ "derfile", 1, 0, 'D' },
	{ "gen", 0, 0, 'g' },
	{ "help", 0, 0, 'h' },
	{ "hba", 0, 0, 'H'},
#ifdef	USE_CONSOLE
	{ "interactive", 0, 0, 'i' },
#endif
	{ "iface", 1, 0, 'I' },
	{ "keyfile", 1, 0, 'k' },
	{ "name", 1, 0, 'N' },
	{ "deroutfile", 1, 0, 'o' },
	{ "prefix", 1, 0, 'p' },
	{ "rsa <bits>", 1, 0, 'R' },
	{ "sec", 0, 0, 's' },
	{ "sigmeth", 1, 0, 'S' },
	{ "use", 1, 0, 'U' },
	{ "ver", 0, 0, 'v' },
	{ "version", 0, 0, 'V' },
	{ 0 }
};

/* Keep these in sync with cmd_opts */
static const char *cmd_exps[] = {
	"IPv6 address to verify",
	"Configuration file",
	"File containing an X509 certificate",
	"Turn on verbose debugging, if built with APPLOG_DEBUG",
	"File containing DER-encoded CGA parameters",
	"Generate a new CGA or set of HBAs",
	"Show this help synopsis",
	"Use HBA mode instead of CGA",
#ifdef	USE_CONSOLE
	"Run with an interactive console",
#endif
	"Specify an interface for an address (add only)",
	"File containing a PEM-encoded RSA key pair",
	"Name for named parameters",
	"Output file for DER-encoded parameters produced by gen",
	"IPv6 address specifying a prefix for gen",
	"Generate a new RSA key for use with gen (<bits> is mandatory)",
	"Specify a CGA sec value for generation",
	"Specify a signature method name",
	"Specify named parameters to use",
	"Verify a CGA",
	"Show version"
};

static void
usage(const char *this)
{
	struct option *op;
	const char **exp;

	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s --gen [-cCDHpkqRs]\n", this);
	fprintf(stderr, "  %s --ver [-aDsq]\n", this);
	fprintf(stderr, "  %s --add [-aDkNUIS]\n", this);
#ifdef	USE_CONSOLE
	fprintf(stderr, "  %s -i\n", this);
#endif

	fprintf(stderr, "\nOptions:\n");
	for (op = cmd_opts, exp = cmd_exps; op->name; op++, exp++) {
		printf("  --%-12s(-%c)\t%s\n", op->name, op->val, *exp);
	}
}

int
main(int argc, char **argv)
{
	int c, interactive = 0;
	const char *certfile = NULL;
	const char *conffile = NULL;
	const char *derfile = NULL;
	const char *deroutfile = NULL;
	const char *keyfile = NULL;
	const char *addrstr = NULL;
	const char *pfxstr = NULL;
	const char **pfxstrs = NULL; /*For HBA*/
	int         npfxs=0;
	const char *rsa_bits = NULL;
	const char *name = NULL;
	const char *ifname = NULL;
	const char *use = NULL;
	int gen = 0;
	int ver = 0;
	int debug = 0;

	if (applog_open(L_STDERR, "cgatool") < 0) {
		return (1);
	}
	if ((cga = new_cga_ctx()) == NULL) {
		return (-1);
	}
	atexit(free_ctx);

	while ((c = getopt_long_only(argc, argv,
				     "a:Ac:C:dD:EghHiI:k:N:o:p:R:s:S:U:vV",
				     cmd_opts, NULL))
	       != -1) {
		switch (c) {
		case 'a':
			addrstr = optarg;
			break;
		case 'c':
			conffile = optarg;
			break;
		case 'C':
			certfile = optarg;
			break;
		case 'd':
			debug++;
			break;
		case 'D':
			derfile = optarg;
			break;
		case 'g':
			gen = 1;
			break;
		case 'h':
			usage(*argv);
			exit(0);
		case 'H':
			hba = 1;
			break;
		case 'I':
			ifname = optarg;
			break;
#ifdef	USE_CONSOLE
		case 'i':
			interactive = 1;
			break;
#endif
		case 'k':
			keyfile = optarg;
			break;
		case 'N':
			name = optarg;
			break;
		case 'p':
			if (!hba) pfxstr = optarg;
			else {
				npfxs++;
				pfxstrs=realloc(pfxstrs,npfxs*sizeof(char*));
				if (!pfxstrs) {
					APPLOG_NOMEM();
					return EXIT_FAILURE;
				}
				pfxstrs[npfxs-1]=optarg;
			}
			break;
		case 'o':
			deroutfile = optarg;
			break;
		case 'R':
			rsa_bits = optarg;
			break;
		case 's':
			if (do_set_sec(optarg) < 0) {
				exit(1);
			}
			break;
		case 'U':
			use = optarg;
			break;
		case 'v':
			ver = 1;
			break;
		case 'V':
			fprintf(stderr, "cgatool. Tool for generating CGAs\n"
				"\tOriginal code from the DoCoMo SEND" 
				" implemenation\n"
				"Modified by S. Barré for LinShim6 version "
				VERSION "\n");
			exit(0);
		default:
			fprintf(stderr, "invalid flag '%c'\n", c);
			usage(*argv);
			exit(1);
		}
	}


	if (!gen && !ver && !interactive) {
		usage(*argv);
		exit(1);
	}

#ifdef	APPLOG_DEBUG
	if (debug) {
		applog_addlevel(log_all_on);
	}
#endif
	if (cga_init() < 0) {
		exit(1);
	}
	if (ssl_thread_init() < 0) {
		exit(1);
	}
	atexit(ssl_thread_cleanup);

	if (rsa_bits && !keyfile) {
		fprintf(stderr, "Need to specify an output keyfile with -k "
			"when generating a key\n");
		exit(1);
	}

	if ((conffile && read_config(conffile) < 0) ||
	    (certfile && do_load_cert(certfile) < 0) ||
	    (derfile && do_readder(derfile) < 0) ||
	    (!rsa_bits && keyfile && do_load_key(keyfile) < 0) ||
	    (addrstr && do_set_address(addrstr) < 0) ||
	    (pfxstr && do_set_prefix(pfxstr) < 0) ||
	    (pfxstrs && do_set_prefixes(pfxstrs,npfxs) < 0) ||
	    (rsa_bits && do_gen_rsa(rsa_bits, keyfile) < 0) ||
	    (!keyfile && !derfile && hba && do_gen_pseudokey()<0)) {
		printf("failed\n");
		exit(1);
	}
	
	c = 0;
	if (gen) {
		if (!interactive && !deroutfile) {
			fprintf(stderr, "Need to specify a deroutfile with "
				"-o\n");
			exit(1);
		}
		c = do_gen(NULL);
	}
	if (c == 0 && ver) {
		c = do_ver(NULL);
	}
	if (c == 0 && deroutfile) {
		if (!cga->der_set) {
			fprintf(stderr, "deroutfile specified, but DER is "
				"not set\n");
		} else {
			c = do_writeder(deroutfile);
		}
	}

	if (!interactive) {
		exit(c);
	}

#ifdef	USE_CONSOLE
	if (console_init(0, 1, cmds, sizeof (cmds) / sizeof (*cmds), exitcb,
			 "cga> ") < 0) {
		fprintf(stderr, "console_init failed\n");
		return (1);
	}

	c = do_select(0);
#endif
	exit(c);
}
