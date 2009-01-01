/*
 *
 * This file comes from the DoCoMo SEND project (params.c)
 *
 * Adapted by Sébastien Barré - sebastien.barre@uclouvain.be
 *
 *
 * Copyright © 2006, DoCoMo Communications Laboratories USA, Inc.,
 *   the DoCoMo SEND Project
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

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>

#include <hashtbl.h>
#include <applog.h>
#include <list.h>
#include <cga.h>
#include <utils/debug.h>

#include <cryptoshim6/cga_params.h>
#include <cryptoshim6/sigmeth.h>
#include <cryptoshim6/sig_RSASSA-PKCS1-v1_5.h>
#include <cryptoshim6/cga.h>

#define DEF_CGA_PARAMS_FILE CONFIG_DIR "/cgad/params.conf"
#define	CGAD_HASH_SZ	7

enum cgadctl_status {
	CGADCTL_STATUS_OK,
	CGADCTL_STATUS_PROTOERR,
	CGADCTL_STATUS_INVAL,
	CGADCTL_STATUS_NOMEM,
	CGADCTL_STATUS_NOENT,
	CGADCTL_STATUS_BUSY,
	CGADCTL_STATUS_SYSERR,
	CGADCTL_STATUS_BADMETH,
};

struct cgad_named_params {
	struct list_head	list;
	const char *		name;
	int			free_params;
	const char		*using;
	struct cga_params	*params;
};

struct cgad_addr_params {
	htbl_item_t		hit;
	struct in6_addr		addr;
	int			ifidx;
	int			free_params;
	const char		*using;
	struct cga_params	*params;
};

static LIST_HEAD(named_params);
LIST_HEAD(hba_sets);
static htbl_t *addr_params;

static uint32_t
hash_ent(void *a, int sz)
{
	struct cgad_addr_params *p = a;
	return (hash_in6_addr(&p->addr, sz));
}

static int
match_ent(void *a, void *b)
{
	struct cgad_addr_params *x = a;
	struct cgad_addr_params *y = b;

	if (x->ifidx != y->ifidx) {
		return (x->ifidx - y->ifidx);
	}
	return (memcmp(&x->addr, &y->addr, sizeof (x->addr)));
}

static struct cgad_addr_params *
_find_params_byaddr(struct in6_addr *a, int ifidx)
{
	struct cgad_addr_params k[1];

	k->addr = *a;
	k->ifidx = ifidx;
	return (htbl_find(addr_params, k));
}

uint8_t *
cgad_readder(const char *fname, int *dlen)
{
	struct stat sb[1];
	FILE *fp;
	uint8_t *der;

	if (stat(fname, sb) < 0) {
		applog(LOG_ERR, "%s: Could not stat file '%s': %s",
		       __FUNCTION__, fname, strerror(errno));
		return (NULL);
	}

	if ((fp = fopen(fname, "r")) == NULL) {
		applog(LOG_ERR, "%s: Could not open file '%s': %s",
		       __FUNCTION__, fname, strerror(errno));
		return (NULL);
	}

	if ((der = malloc(sb->st_size)) == NULL) {
		APPLOG_NOMEM();
		fclose(fp);
		return (NULL);
	}

	if (fread(der, 1, sb->st_size, fp)!=sb->st_size) {
		applog(LOG_ERR, "%s: Could not read file '%s': %s",
		       __FUNCTION__, fname, strerror(errno));
		return (NULL);
	}
	fclose(fp);
	*dlen = sb->st_size;

	return (der);
}

static struct hba_set* find_hbaset_byname(const char* name)
{
	struct hba_set* s;
	list_for_each_entry(s, &hba_sets,list) {
		if (strcasecmp(name,s->name)==0) {
			return s;
		}
	}
	return NULL;
}

static struct cgad_named_params *
find_params_byname(const char *name)
{
	struct cgad_named_params *p;

	list_for_each_entry(p, &named_params, list) {
		if (strcasecmp(name, p->name) == 0) {
			return (p);
		}
	}

	return (NULL);
}

struct cga_params *
find_params_byaddr(struct in6_addr *a, int ifidx)
{
	struct cgad_addr_params *p;

	if ((p = _find_params_byaddr(a, ifidx)) != NULL) {
		return (p->params);
	}
	return (find_params_byifidx(ifidx));
}

struct cga_params *
find_params_byifidx(int ifidx)
{
	char ifname[IF_NAMESIZE];
	struct cgad_named_params *p;

	if (if_indextoname(ifidx, ifname) == NULL) {
		applog(LOG_ERR, "%s: can't map ifidx %d to name",
		       __FUNCTION__, ifidx);
		return (NULL);
	}

	if ((p = find_params_byname(ifname)) != NULL) {
		return (p->params);
	}
	p = find_params_byname("default");
	return (p->params);
}

/* XXX now that we can delete arbitrary params, we need to refcnt each
 * usage of a set of given params
 */
static void
free_cga_params(struct cga_params *p)
{
	if (p->der) free(p->der);
	if (p->key) p->sigmeth->free_key(p->key);
	free(p);
}

static void
free_addr_params(struct cgad_addr_params *p)
{
	if (p->free_params) {
		put_cga_params(p->params);
	}
	free(p);
}

static void
free_named_params(struct cgad_named_params *p)
{
	if (p->free_params) {
		put_cga_params(p->params);
	}
	free(p);
}

static int _add_named_hbaset(struct hba_set *set)
{
	if (find_hbaset_byname(set->name) != NULL) {
		applog(LOG_WARNING, "%s:hba set %s already configured", 
		       __FUNCTION__,set->name);
		return 0;
	}
	list_add_tail(&set->list, &hba_sets);
	return 0;
}

static int
_add_named_params(const char *name, struct cga_params *params,
		  int free_params, const char *use)
{
	struct cgad_named_params *p;

	if ((p = find_params_byname(name)) != NULL) {
		applog(LOG_WARNING, "%s: %s already configured", __FUNCTION__,
		       name);
		return (0);
	}
	if ((p = malloc(sizeof (*p))) == NULL) {
		APPLOG_NOMEM();
		return (CGADCTL_STATUS_NOMEM);
	}
	memset(p, 0, sizeof (*p));

	if ((p->name = strdup(name)) == NULL) { // XXX need to free this, but be careful dangling refs
		free(p);
		APPLOG_NOMEM();
		return (CGADCTL_STATUS_NOMEM);
	}

	p->free_params = free_params;
	p->params = params;
	p->using = use;
	list_add_tail(&p->list, &named_params);

	return (0);
}

static int
_add_addr_params(struct in6_addr *a, int ifidx,
    struct cga_params *params, int free_params, const char *use)
{
	struct cgad_addr_params *p;
	char abuf[INET6_ADDRSTRLEN];

	if (_find_params_byaddr(a, ifidx) != 0) {
		applog(LOG_WARNING, "%s: %s already configured", __FUNCTION__,
		       inet_ntop(AF_INET6, a, abuf, sizeof (abuf)));
		return (0);
	}

	if ((p = malloc(sizeof (*p))) == NULL) {
		APPLOG_NOMEM();
		return (CGADCTL_STATUS_NOMEM);
	}
	memset(p, 0, sizeof (*p));

	p->addr = *a;
	p->ifidx = ifidx;
	p->free_params = free_params;
	p->params = params;
	p->using = use;
	htbl_add(addr_params, p, &p->hit);

	return (0);
}

/**
 * @post -If hs is NULL, the structure is created but not the CGAs (generated 
 *          later upon reception of RAs)
 *       -if hs is not NULL, the structure is created and a new HBA set of 
 *        addresses is generated and stored in the structure.
 *        The der parameter is also checked to be consistent with the given HBA
 *        set. If no multiprefix extension is present, it is added. If a
 *        multiprefix extension is present, but the prefix list is different
 *        from that of @hs, @status is set to CGADCTL_STATUS_INVAL, and
 *        NULL is returned.
 *       -Consistency between @sec and the der is also checked, and @status is
 *        set to CGADCTL_STATUS_INVAL, and NULL returned is @sec and the sec
 *        parameter of the der are different.
 */

static struct cga_params *
new_cga_params(uint8_t *der, int dlen, void *key, int sec,
	       struct sig_method *m, struct hba_set* hs, 
	       enum cgadctl_status *status)
{
	struct cga_params *p;
	cga_ctx_t ctx[1];			
	
	cga_init_ctx(ctx);
	cga_set_der(ctx, der, dlen);
	cga_set_sec(ctx, sec);

	/*If an hs is defined but no multiprefix extension is 
	  present, autogenerate it*/
	if (hs) {
		hba_set_prefixes(ctx,hs);
		if (hba_autogen_mpe(ctx)<0) {
			applog(LOG_ERR,"%s: hba_autogen_mpe failed",
			       __FUNCTION__);
			*status = CGADCTL_STATUS_SYSERR;
			return NULL;
		}
		/*Getting the new pointers*/
		der=ctx->der;
		dlen=ctx->derlen;
	}

	if ((p = malloc(sizeof (*p))) == NULL) {
		APPLOG_NOMEM();
		free(der);
		if (key) m->free_key(key);
		*status = CGADCTL_STATUS_NOMEM;
		return (NULL);
	}
	bzero(p,sizeof(*p));
	p->key = key;
	p->sigmeth = m;
	p->der = der;
	p->dlen = dlen;
	p->sec = sec;
	p->refcnt = 1;

	if (sigmeth_params_init(m, p) == 0) {
		*status = CGADCTL_STATUS_OK;
	} else {
		*status = CGADCTL_STATUS_SYSERR;
		free_cga_params(p);
		p = NULL;
	}

	if (hs) {
		p->hs=hs;
		if (hba_precompute(p)<0) {
			*status = CGADCTL_STATUS_SYSERR;
			free_cga_params(p);
			p = NULL;			
		}
		hs=ctx->hba_data=p->hs; /*The hs pointer has been changed*/
		PDEBUG("hs->length : %d",hs->length);
	}
	else p->hs=NULL;

	if (cga_validate_ctx(ctx)<0) {
		*status=CGADCTL_STATUS_INVAL;
		free_cga_params(p);
		return NULL;
	}

	return (p);
}

static struct cga_params *
create_cga_params(const char *name, const char *derfile,
		  const char *keyfile, int sec, struct sig_method *m, 
		  const char* use_hbaset, enum cgadctl_status *status)
{
	uint8_t *der;
	int dlen;
	void *key=NULL;
	struct hba_set *hs=NULL;
	struct cga_params *p;
	int cgacompat=0;

	if (use_hbaset && (hs = find_hbaset_byname(use_hbaset))==NULL) {
		applog(LOG_ERR, "%s: Can't find hbaset %s", __FUNCTION__,
		       use_hbaset);
		*status=CGADCTL_STATUS_NOENT;
		return NULL;
	}

	if (m == NULL &&
	    (m = find_sig_method_byname(RSASSA_PKCS1_V1_5_SIGMETH)) == NULL) {
		applog(LOG_ERR, "%s: Can't find any valid signature method!",
		       __FUNCTION__);
		*status = CGADCTL_STATUS_SYSERR;
		return (NULL);
	}

	if ((der = cgad_readder(derfile, &dlen)) == NULL) {
		applog(LOG_ERR, "%s: reading params failed for %s",
		       __FUNCTION__, name);
		*status = CGADCTL_STATUS_INVAL;
		return (NULL);
	}
	
	/*The keyfile is not needed if we are dealing with
	 * HBA only addresses*/
	if (keyfile || !hs) {
		if ((key = m->load_key(keyfile)) == NULL) {
			free(der);
			applog(LOG_ERR, "%s: reading key failed for %s",
			       __FUNCTION__, name);
			*status = CGADCTL_STATUS_INVAL;
			return (NULL);
		}
		else if (hs) cgacompat=1;
	}
	p=new_cga_params(der, dlen, key, sec, m, hs, status);
	if (p->hs) p->hs->cgacompat=cgacompat;
	return p;
}

int add_named_hbaset(const char* name,uint64_t* set, int length)
{
	enum cgadctl_status st;
	struct hba_set *s;
	if ((s=new_hbaset_pfx(name,set,length))==NULL) 
		return CGADCTL_STATUS_NOMEM;
	st=_add_named_hbaset(s);
	return st;
}

int
add_named_params(const char *name, const char *derfile,
		 const char *keyfile, int sec, struct sig_method *m,
		 char* use_hbaset)
{
	struct cga_params *p;
	enum cgadctl_status st;

	if ((p = create_cga_params(name, derfile, keyfile, sec, m, 
				   use_hbaset,&st)) == NULL) {
		return (st);
	}
	if ((st = _add_named_params(name, p, 1, NULL)) != 0) {
		free_cga_params(p);
	}
	return (st);
}

int
add_named_params_use(const char *name, const char *use)
{
	struct cgad_named_params *p;
	enum cgadctl_status st;

	if ((p = find_params_byname(use)) == NULL) {
		applog(LOG_ERR, "%s: Can't find params %s", __FUNCTION__,
		       use);
		return (CGADCTL_STATUS_NOENT);
	}

	hold_cga_params(p->params);
	if ((st = _add_named_params(name, p->params, 0, p->name)) != 0) {
		put_cga_params(p->params);
	}
	return (st);
}

int
add_addr_params(struct in6_addr *a, int ifidx, const char *derfile,
		const char *keyfile, int sec, struct sig_method *m,
		char* use_hbaset)
{
	struct cga_params *p;
	enum cgadctl_status st;

	if ((p = create_cga_params("addr", derfile, keyfile, sec, m, 
				   use_hbaset, &st))
	    == NULL) {
		return (st);
	}
	if ((st = _add_addr_params(a, ifidx, p, 1, NULL)) != 0) {
		free_cga_params(p);
	}
	return (st);
}

int
add_addr_params_use(struct in6_addr *a, int ifidx, const char *use)
{
	struct cgad_named_params *p;
	enum cgadctl_status st;

	if ((p = find_params_byname(use)) == NULL) {
		applog(LOG_ERR, "%s: Can't find params %s", __FUNCTION__, use);
		return (CGADCTL_STATUS_NOENT);
	}

	hold_cga_params(p->params);
	if ((st = _add_addr_params(a, ifidx, p->params, 0, p->name)) != 0) {
		put_cga_params(p->params);
	}
	return (st);
}

int
del_addr_params(struct in6_addr *a, int ifidx)
{
	struct cgad_addr_params *p;

	if ((p = _find_params_byaddr(a, ifidx)) == NULL) {
		return (CGADCTL_STATUS_NOENT);
	}
	if (!p->using && p->params->refcnt > 1) {
		return (CGADCTL_STATUS_BUSY);
	}
	htbl_rem_hit(addr_params, &p->hit);
	free_addr_params(p);
	return (0);
}

int
del_named_params(const char *name)
{
	struct cgad_named_params *p;

	if ((p = find_params_byname(name)) == NULL) {
		return (CGADCTL_STATUS_NOENT);
	}
	/* Don't delete if this is being referenced */
	if (!p->using && p->params->refcnt > 1) {
		return (CGADCTL_STATUS_BUSY);
	}

	list_del(&p->list);
	free_named_params(p);
	return (0);
}

static int
read_cga_params(void)
{
	const char *f = DEF_CGA_PARAMS_FILE;

	if (f == NULL) {
		return (0);
	}

	if ((params_in = fopen(f, "r")) == NULL) {
		applog(LOG_ERR, "%s: fopen(%s): %s", __FUNCTION__, f,
		       strerror(errno));
		return (-1);
	}

	if (params_parse() != 0) {
		return (-1);
	}

	fclose(params_in);
	return (0);
}

void
hold_cga_params(struct cga_params *p)
{
	p->refcnt++;
}

void
put_cga_params(struct cga_params *p)
{
	p->refcnt--;
	if (p->refcnt == 0) {
		free_cga_params(p);
	}
}

static void
hexdump(int fd, uint8_t *b, int len, char *indent)
{
	int i;

	if (indent) dprintf(fd,"%s",indent);
	for (i = 0; i < len; i++) {
		int v = b[i] & 0xff;
		dprintf(fd,"%.2x ", v);

		if (((i + 1) % 16) == 0) {
			dprintf(fd,"\n");
			if (indent) dprintf(fd,"%s",indent);
		} else if (((i + 1) % 8) == 0) {
			dprintf(fd," ");
		}
	}
	dprintf(fd,"\n");
}

static void
dump_cga_params(int fd,struct cga_params *p)
{
	dprintf(fd, "\tref: %d sig method: %s (%d)\n", p->refcnt, 
		p->sigmeth->name, p->sigmeth->type);
	hexdump(fd, p->der, p->dlen, "\t");
}

static void
dump_walker(void *p, void *c)
{
	struct cgad_addr_params *pa = p;
	int fd=*(int*)c;
	char abuf[INET6_ADDRSTRLEN];

	dprintf(fd,"%-25s  sec %d ifidx %d %s%s\n",
	       inet_ntop(AF_INET6, &pa->addr, abuf, sizeof (abuf)),
	       pa->params->sec, pa->ifidx,
	       pa->using ? "use: " : "", pa->using ? pa->using : "");
	if (!pa->using) {
		dump_cga_params(fd,pa->params);
	}
}

void
dump_params(int fd)
{
	struct cgad_named_params *pn;

	list_for_each_entry(pn, &named_params, list) {
		dprintf(fd,"%-25s  sec %d %s%s\n", pn->name,
			pn->params->sec,
			pn->using ? "use: " : "", pn->using ? pn->using : "");
		if (!pn->using) {
			dump_cga_params(fd,pn->params);
		}
	}

	htbl_walk(addr_params, dump_walker, &fd);
}

int
cgad_params_init(void)
{
	if ((addr_params = htbl_create(CGAD_HASH_SZ, hash_ent, match_ent))
	    == NULL) {
		applog(LOG_ERR, "%s: htbl_create() failed", __FUNCTION__);
		return (-1);
	}

	if (read_cga_params() < 0) {
		return (-1);
	}
	if (find_params_byname("default") == NULL) {
		applog(LOG_ERR, "%s: missing 'default' params", __FUNCTION__);
		return (-1);
	}

	return (0);
}

void
cgad_params_fini(void)
{
	// XXX improve cleanup - list too
	if (addr_params) htbl_destroy(addr_params, free);
}
