/*
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

/**
 * Core CGA functions, including address generation and verification,
 * as well as helper functions.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <config.h>
#include <applog.h>
#include <utils/debug.h>

#include <cga.h>
#include <cga_keyutils.h>
#include "cga_local.h"

#ifdef	APPLOG_DEBUG
static char abuf[INET6_ADDRSTRLEN];
#endif

const char *cga_version = "DoCoMo CGA library 0.0 (rfc3972)";

#ifndef	s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

/*
 * We need to initialize libcrypto by loading cipher, digest, and
 * encryption algorithms, and also by loading error strings. We only
 * want to do this once, the first time cga_generate() or cga_verify()
 * is called, so we use cga_initialized to keep this state and initlock
 * to protect it. cga_init() does the actual initialization work.
 */
static int cga_initialized = 0;
static pthread_mutex_t initlock = PTHREAD_MUTEX_INITIALIZER;

void setbits(uint8_t *id, uint8_t sec)
{
	/* Turn off U and G bits, zero sec bits */
	id[0] &= 0x1c;

	/* Set sec bits */
	id[0] |= (sec << 5);

	DBG(&dbg_gen, "sec parameter : %d\n", sec);
	DBG_HEXDUMP(&dbg_gen, "interface identifier: ", id, 8);
}

/**
 * Concatenates an IPv6 prefix and digest to form an IPv6 address.
 *
 * pfx: the prefix
 * hash: the digest
 * addr: a buffer into which the address will be placed.
 */
void concat(uint64_t *pfx, uint8_t *hash, struct in6_addr *addr)
{
	memcpy(addr,pfx,sizeof(*pfx));
	memcpy(addr->s6_addr + 8, hash, 8);

	DBG(&dbg_gen, "%s", inet_ntop(AF_INET6, addr, abuf, INET6_ADDRSTRLEN));
}

uint8_t *
cga_parse_key(uint8_t *p, int *klenp)
{
	int klen, c, i, t;
	uint8_t *ap;

	/* calculate klen from ASN.1 */
	if (!(p[1] & 0x80)) {
		/* only 1 length octet */
		klen = p[1];
		klen += 2; /* type + length */
	} else {
		/* multiple length octets */
		c = p[1] & ~0x80;
		klen = 0;
		for (ap = p + 2, i = c; i > 0; i--, ap++) {
			t = *ap;
			t <<= ((i - 1) * 8);
			klen += t;
		}
		klen += 2 + c; /* type + length octets */
	}

	*klenp = klen;
	return (p + klen);
}

uint8_t *
cga_get_multikey_key(uint8_t *hdr, int *klen)
{
	struct cga_multikey_ext *ext = (struct cga_multikey_ext *)hdr;
	uint16_t blen;

	/* klen might not be aligned, so use memcpy */
	memcpy(&blen, &ext->klen, sizeof (ext->klen));
	*klen = ntohs(blen);

	return (ext->key);
}

int
cga_parse_next_ext(uint8_t *p, int rem, int *elen, uint16_t *type)
{
	struct cga_ext_hdr *ext;
	int t, blen;

	if (rem < sizeof (*ext)) {
		DBG(&dbg_asn1, "not enough for ext hdr (%d / %d)", rem,
		    sizeof (*ext));
		return (-1);
	}
	ext = (struct cga_ext_hdr *)p;
	/* type and len might not be aligned, so use memcpy */
	memcpy(&t, &ext->type, sizeof (ext->type));
	*type = ntohs(t);
	memcpy(&blen, &ext->len, sizeof (ext->len));
	*elen = ntohs(blen)+sizeof(struct cga_ext_hdr);

	if (*elen > rem) {
		DBG(&dbg_asn1, "not enough for ext (%d / %d)", rem, *elen);
		DBG(&dbg_asn1, "Extension type is : %d", *type);
		return (-1);
	}

	return (0);
}

int
ws_parse_common(struct cga_parsed_params *ws)
{
	uint8_t *p = ws->buf;
	int elen, totlen, rem;
	uint16_t type;

	ws->mod = p;
	p += CGA_MODLEN;

	ws->pfx = p;
	p += 8;

	ws->col = p;
	p++;

	rem = ws->dlen - CGA_PARAM_LEN;
	if (rem <= 0) {
		DBG(&dbg_asn1, "missing key in CGA params");
		return (-1);
	}

	/* Get first key len (not in an extension) */
	ws->key = p;
	cga_parse_key(p, &ws->klen);
	if (ws->klen > rem) {
		/* bad asn.1 length; truncate to prevent too much trouble.. */
		ws->klen = ws->dlen - CGA_PARAM_LEN;
	}
	p += ws->klen;
	totlen = 0;
	
	/*Initializing ext fields*/
	ws->mpe=NULL;
	
	for (rem -= ws->klen; rem > 0; rem -= elen) {
		if (cga_parse_next_ext(p, rem, &elen, &type) < 0) {
			applog(LOG_ERR,"%s:cga_parse_next_ext failed",
			       __FUNCTION__);
			return (-1);
		}
		if (type==CGA_MULTIPFX_EXT)
			ws->mpe=(struct cga_multipfx_ext*)p;		       
		totlen += elen;
		p += elen;
	}

	return (0);
}

/*
 * Adds a key to the CGA parameters. The first key is simply appended
 * to the end of the CGA params, per rfc3972. If this is not the first
 * key, the key is appended in a key extension of type 'type'.
 */
int
cga_add_key(cga_ctx_t *cga, EVP_PKEY *k, int first, uint16_t type)
{
	uint8_t *dk;
	struct cga_multikey_ext *ext;
	int klen, extlen = sizeof (*ext);
	uint16_t t, blen;

	if ((dk = cga_key2der(k, &klen)) == NULL) {
		return (-1);
	}

	if (first) {
		extlen = klen;
	} else {
		extlen += klen;
	}

	if ((cga->key = realloc(cga->key, cga->klen + extlen)) == NULL) {
		APPLOG_NOMEM();
		return (-1);
	}
	cga->free_key = 1;
	cga->key_set = 1;

	if (first) {
		memcpy(cga->key + cga->klen, dk, klen);
		cga->klen += klen;
		return (0);
	}

	/* Add in an extension */
	ext = (struct cga_multikey_ext *)(cga->key + cga->klen);

	/* type, len and klen may not be aligned, so use memcpy */
	t = htons(type);
	memcpy(&ext->hdr.type, &t, sizeof (ext->hdr.type));

	blen = htons(extlen-sizeof(struct cga_ext_hdr));
	memcpy(&ext->hdr.len, &blen, sizeof (ext->hdr.len));

	blen = htons(klen);
	memcpy(&ext->klen, &blen, sizeof (ext->klen));
	memcpy(ext->key, dk, klen);

	cga->klen += extlen;

	return (0);
}

/**
 * @pre : cga->der==ws->buf
 * @post: -The memory area pointed to by ws->buf is realloc'ed (to take
 *        into account the new multiprefix extension).
 *        -the ws->buf, ws->dlen, cga->der and cga->derlen are adapted 
 *         accordingly.
 */
int cga_add_multipfx_ext(struct cga_parsed_params *ws, cga_ctx_t *cga)
{
	struct cga_multipfx_ext *ext;
	int extlen;
	
	ASSERT(cga->der==ws->buf);

	if (!cga->prefixes_set) {
		applog(LOG_ERR,"%s : Prefixes are not defined",__FUNCTION__);
		return -1;
	}
	if (!cga->hba_data) {
		applog(LOG_ERR,"%s : hba set prefixes not defined",
		       __FUNCTION__);
		return -1;
	}
	if (cga->hba_data->computed) {
		applog(LOG_ERR,"%s : The HBA addresses have already been " 
		       "computed", __FUNCTION__);
		return -1;
	}

	extlen=sizeof(*ext)+
		cga->hba_data->length*sizeof(uint64_t);

	PDEBUG("%s : Realloc'ed DER",__FUNCTION__);
	if ((ws->buf=cga->der=realloc(ws->buf,ws->dlen+extlen))==NULL) {
		APPLOG_NOMEM();
		return -1;
	}

	ext=(struct cga_multipfx_ext*)(ws->buf+ws->dlen);
	ext->hdr.type=htons(CGA_MULTIPFX_EXT);
	ext->hdr.len=htons(extlen-sizeof(struct cga_ext_hdr));
	ext->P=~(cga->pseudo_key);
	ext->reserved=0;
	memcpy(ext->pfxs,cga->hba_data->set_pfx,
	       cga->hba_data->length*sizeof(uint64_t));
	
	ws->dlen=cga->derlen=ws->dlen+extlen;
		
	PDEBUG("Added multipfx extension, with length %d\n",extlen);
	
	return 0;
}

int
cga_parse_params(struct cga_parsed_params *ws)
{
	uint8_t *p;

	if ((p = ws->buf) == NULL) {
		DBG(&dbg_ver, "ws->buf is NULL");
		return (-1);
	}

	if (ws->dlen < CGA_PARAM_LEN) {
		DBG(&dbg_ver, "len too short for CGA params");
		return (-1);
	}

	return (ws_parse_common(ws));
}

static int ws_copy(struct cga_parsed_params* wsc, struct cga_parsed_params* ws)
{
	bzero(wsc,sizeof(*wsc));
	if (!(wsc->buf=malloc(ws->dlen))) {
		APPLOG_NOMEM();
		return -1;
	}
	wsc->dlen=ws->dlen;
	memcpy(wsc->buf,ws->buf,ws->dlen);
	if (ws_parse_common(wsc) < 0) {
		applog(LOG_ERR,"%s:ws_parse_common failed",__FUNCTION__);
		free(wsc->buf);
		return (-1);
	}
	return 0;
}

/**
 * Validates the cga context, by verifying consistency between the der and
 * and the encoded parameters. Returns 0 in case of success, or a negative
 * error code if any inconsistency is found.
 *
 * This function is not necessary for the security, but it is highly useful 
 * to indicate misconfigurations from the user.
 */
int cga_validate_ctx(cga_ctx_t* cga)
{
	struct cga_parsed_params ws[1];
	struct cga_parsed_params wsc[1];

	PDEBUG("cga->hba_data : %p",cga->hba_data);
	
	wsc->buf=NULL;

	if (!cga->der)  {
		applog(LOG_ERR, "%s: der field is not defined", __FUNCTION__);
		return -1;
	}
	bzero(ws, sizeof (*ws));
	ws->buf=cga->der;
	ws->dlen=cga->derlen;
	if (ws_parse_common(ws) < 0) {
		applog(LOG_ERR,"%s:ws_parse_common failed",__FUNCTION__);
		goto fail;
	}

	if (ws_copy(wsc,ws)<0) {
		applog(LOG_ERR,"%s:ws_copy failed",__FUNCTION__);
		goto fail;
	}
	memset(wsc->pfx, 0, 8);
	*(wsc->col) = 0;

	DBG_HEXDUMP(&dbg_gen, "initial der: ", wsc->buf, wsc->dlen);

	if (cga_findmod_mt(cga->batchsize, wsc->buf, wsc->mod, 
			   wsc->dlen,
			   cga->sec, cga->thrcnt) < 0) {		
		applog(LOG_ERR,"%s:cga_findmod_mt failed",__FUNCTION__);
		goto fail;
	}
	DBG_HEXDUMP(&dbg_gen, "found modifier: ", wsc->mod, CGA_MODLEN);

	/*Check the sec parameter : The only easy way I see for doing it, since
	  the sec param is stored nowhere, is to re-generate the modifier
	  and compare it against the original one. If sec is correct, this check
	  is O(1) anyway.*/
	if (memcmp(wsc->mod, ws->mod,CGA_MODLEN)) {
		applog(LOG_ERR,"%s:Invalid modifier, the sec parameter\n"
		       "is probably not consistent with the der.",__FUNCTION__);
		goto fail;
	}

	/*Checking the HBA prefix list*/
	if (cga->prefixes_set) {
		int i;
		if (!ws->mpe) {
			applog(LOG_ERR,"%s:The der contains no multiprefix "
			       "extension", __FUNCTION__);
			goto fail;
		}
		if ((ntohs(ws->mpe->hdr.len)-4)>>3 != cga->hba_data->length) {
			applog(LOG_ERR,"%s:The length of the der multiprefix "
			       "extension differs from that of the hba_set : "
			       " ext:%d/set:%d",__FUNCTION__,
			       ntohs(ws->mpe->hdr.len),cga->hba_data->length);
			goto fail;
		}
		for (i=0;i<cga->hba_data->length;i++) {
			if (memcmp(&ws->mpe->pfxs[i],cga->hba_data->computed?
				   (void*)(&cga->hba_data->set_addr[i]):
				   (void*)(&cga->hba_data->set_pfx[i]),8)!=0) {
				applog(LOG_ERR,"%s:Prefix at index %d, differs "
				       "between der multiprefix extension "
				       "and the hba_set",__FUNCTION__,i);
				goto fail;
			}
		}
	}

	free (wsc->buf);
	return 0;
fail:
	if (wsc->buf) free(wsc->buf);
	return -1;
}

int
cga_init_generation(struct cga_parsed_params *ws, cga_ctx_t *cga)
{
	uint8_t *buf;

	if (cga->der != NULL && !cga->free_der) {
		PDEBUG("der already defined, no malloc\n");
		ws->buf = cga->der;
		ws->dlen = cga->derlen;
	} else if ((buf = malloc(cga->klen + CGA_PARAM_LEN)) 
		   == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (-1);
	} else {
		if (cga->der) {
			free(cga->der);
		}
		cga->der = ws->buf = buf;
		cga->derlen = ws->dlen = CGA_PARAM_LEN + cga->klen;
		cga->free_der = 1;

		memcpy(buf + CGA_PARAM_LEN, cga->key, cga->klen);
		if (cga->prefixes_set && cga_add_multipfx_ext(ws,cga)<0)
			return (-1);
	}

	if (ws_parse_common(ws) < 0) {
		applog(LOG_ERR,"%s:ws_parse_common failed",__FUNCTION__);
		return (-1);
	}
	

	memset(ws->pfx, 0, 8);
	*(ws->col) = 0;

	return (0);
}

/**
 * Gets random bytes.
 *
 * b: a buffer into which to place the random bytes
 * num: number of bytes needed. b must be at least num bytes long.
 *
 * returns 0 on success, -1 on failure
 */
int
get_rand_bytes(uint8_t *b, int num)
{
	int fd = open("/dev/urandom", O_RDONLY);

	if (fd < 0) {
		DBG(&dbg_gen, "failed to open /dev/urandom: %s",
		    strerror(errno));
		return (-1);
	}

	if (read(fd, b, num) < 0) {
		DBG(&dbg_gen, "failed to read from /dev/urandom: %s",
		     strerror(errno));
		close(fd);
		return (-1);
	}

	close(fd);
	return (0);
}

int find_modifier(cga_ctx_t *cga, struct cga_parsed_params *ws)
{
	if (cga->sec == 0) {
		DBG(&dbg_gen, "sec == 0, so setting modifier to 0");
		memset(cga->modifier, 0, CGA_MODLEN);
		memset(ws->mod, 0, CGA_MODLEN);
		return (0);
	}

	/* start with a random number, unless a specific starting number
	   has already been set */
	if (!cga->mod_set && get_rand_bytes(ws->mod, CGA_MODLEN) < 0)
		return (-1);
	else if (cga->mod_set) memcpy(ws->mod,cga->modifier,CGA_MODLEN);

	DBG_HEXDUMP(&dbg_gen, "initial der: ", ws->buf, ws->dlen);

	if (cga_findmod_mt(cga->batchsize, ws->buf, ws->mod, ws->dlen,
	    cga->sec, cga->thrcnt) < 0) {
		return (-1);
	}

	cga_set_modifier(cga, ws->mod);

	DBG_HEXDUMP(&dbg_gen, "found modifier: ", cga->modifier, CGA_MODLEN);

	return (0);
}

/**
 * Converts the most recent SSL error message(s) into normal log
 * format.
 *
 * func: the name of the calling function
 * context: a message providing context for the error
 */
void
ssl_err(const char *func, const char *context) {
#ifdef	APPLOG_DEBUG
	int err, i;
	char buf[120];

	for (i = 10; (err = ERR_get_error()) != 0 && i > 0; i--) {
		DBGF(&dbg_ssl, (char *)func, "%s: %s", context,
		     ERR_error_string(err, buf));
	}
#endif
}

int
cga_set_der(cga_ctx_t *ctx, uint8_t *der, int dlen)
{
	if (ctx->der && ctx->free_der) free(der);
	ctx->der = der;
	ctx->derlen = dlen;
	ctx->free_der = 0;
	ctx->der_set = 1;

	if (cga_parse_params_ctx(ctx) < 0) {
		DBG(&dbg_gen, "Invalid DER params");
		return (-1);
	}
	return (0);
}

uint8_t *
cga_get_der(cga_ctx_t *ctx, int *len)
{
	*len = ctx->derlen;
	return (ctx->der);
}

/**
 * Sets a correct modifier for @ctx
 * @pre : *@mod is such that hash2 has 16*sec leftmost bits to zero.
 */
void
cga_set_modifier(cga_ctx_t *ctx, uint8_t *mod)
{
	memcpy(ctx->modifier, mod, CGA_MODLEN);
	ctx->mod_set = 1;
	ctx->mod_final = 1;
}

/**
 * Sets an initial modifier, that will serve as a starting point
 * to find a final modifier.
 */
void
cga_set_modifier_start(cga_ctx_t *ctx, uint8_t *mod)
{
	memcpy(ctx->modifier, mod, CGA_MODLEN);
	ctx->mod_set = 1;
	ctx->mod_final=0;
}

uint8_t *
cga_get_modifier(cga_ctx_t *ctx)
{
	return (ctx->modifier);
}

void
cga_set_prefix(cga_ctx_t *ctx, struct in6_addr *pfx)
{
	memcpy(&ctx->prefix, pfx, sizeof (ctx->prefix));
	ctx->prefix_set = 1;
}

void
cga_set_addr(cga_ctx_t *ctx, struct in6_addr *addr)
{
	memcpy(&ctx->addr, addr, sizeof (ctx->addr));
	ctx->addr_set = 1;
}

int
cga_set_sec(cga_ctx_t *ctx, int sec)
{
	if (sec < 0 || sec > CGA_MAX_SEC) {
		applog(LOG_ERR, "%s: invalid sec value: %d", sec);
		return (-1);
	}
	ctx->sec = sec;
	return (0);
}

int
cga_set_col(cga_ctx_t *ctx, int col)
{
	if (col < 0 || col > CGA_MAX_COL) {
		applog(LOG_ERR, "%s: invalid collision value: %d", col);
		return (-1);
	}
	ctx->collisions = col;
	return (0);
}

void
cga_gen_cancel(void)
{
	cga_findmod_cancel();
}

/**
 * Allocates and initializes a new CGA/HBA context.
 *
 * returns the CGA context on success, NULL on failure.
 */
cga_ctx_t *
new_cga_ctx(void)
{
	cga_ctx_t *cga;

	if ((cga = malloc(sizeof (*cga))) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (NULL);
	}

	cga_init_ctx(cga);
	return (cga);
}

void
cga_cleanup_ctx(cga_ctx_t *cga)
{
	if (cga->key && cga->free_key) {
		free(cga->key);
	}
	if (cga->der && cga->free_der) {
		free(cga->der);
	}
}

/**
 * Frees a CGA context
 */
void
cga_free_ctx(cga_ctx_t *cga)
{
	cga_cleanup_ctx(cga);
	memset(cga, 0, sizeof (*cga));
	free(cga);
}

int
cga_parse_params_ctx(cga_ctx_t *cga)
{
	struct cga_parsed_params ws[1];

	if (cga->der == NULL) {
		DBG(&dbg_ver, "Params not set");
		return (-1);
	}

	ws->buf = cga->der;
	ws->dlen = cga->derlen;

	if (cga_parse_params(ws) < 0) {
		return (-1);
	}

	if (cga->key && cga->free_key) {
		free(cga->key);
	}
	cga->klen = cga->derlen - CGA_PARAM_LEN;
	cga->key = ws->key;
	cga->free_key = 0;
	memcpy(cga->modifier, ws->mod, CGA_MODLEN);
	memcpy(&cga->prefix, ws->pfx, 8);
	cga->collisions = *ws->col;
	cga->key_set = 1;
	cga->mod_set = 1;

	return (0);
}

/**
 * Generates a new address from the parameters set in the CGA context.
 * See the API documentation for more information on how to set these
 * parameters.
 *
 * returns 0 on success, -1 on failure. On success, the new address is
 * in the cga->addr member.
 */
int
cga_generate(cga_ctx_t *cga)
{
	struct cga_parsed_params ws[1];
	uint8_t hash[SHA_DIGEST_LENGTH];

	if (!cga_ready_to_gen(cga)) {
		applog(LOG_ERR, "%s: CGA context not ready for generation",
		       __FUNCTION__);
		return (-1);
	}

	cga_init();

	memset(ws, 0, sizeof (*ws));
	if (cga_init_generation(ws, cga) < 0) {
		return (-1);
	}

	if (cga->collisions > 0) {
		if (cga->collisions > 3) {
			applog(LOG_CRIT, "%s: collisions > 3; "
			    "we may be under attack", __FUNCTION__);
			return (-1);
		}

		DBG(&dbg_gen, "collisions > 0, jumping to hash1");
		memcpy(ws->mod, cga->modifier, CGA_MODLEN);
		goto hash1;
	}

	if (!cga->mod_set || !cga->mod_final) {
		DBG(&dbg_gen, "--- Finding modifier ---");

		if (find_modifier(cga, ws) < 0) {
			return (-1);
		}
	} else {
		DBG_HEXDUMP(&dbg_gen, "--- Using Modifier ---",
			     cga->modifier, CGA_MODLEN);
		memcpy(ws->mod, cga->modifier, CGA_MODLEN);
	}

hash1:
	memcpy(ws->pfx, &cga->prefix, 8);
	*(ws->col) = cga->collisions;

	DBG_HEXDUMP(&dbg_gen, "Input to hash1:", ws->buf, ws->dlen);

	SHA1(ws->buf, ws->dlen, hash);

	DBG_HEXDUMP(&dbg_ver, "Output of hash1: ", hash, 8);

	DBG(&dbg_gen, "--- Setting bits ---");

	setbits(hash, cga->sec);

	DBG(&dbg_gen, "--- Concatenating prefix and eui64 ---");

	concat((uint64_t*)&cga->prefix, hash, &cga->addr);
	cga->der_set = 1;
	cga->addr_set = 1;

	DBG(&dbg_gen, "generated address is %s",
	     inet_ntop(AF_INET6, &cga->addr, abuf, INET6_ADDRSTRLEN));

	return (0);
}

/**
 * Verifies a CGA address based on the parameters given in the CGA
 * context. See the API documentation for more information on how
 * to set these parameters.
 *
 * returns 0 if the address is verified, -1 if not.
 */
int
cga_verify(cga_ctx_t *cga)
{
	struct cga_parsed_params ws[1];
	int sec, col;
	uint8_t hash[SHA_DIGEST_LENGTH], taddr[8];
	uint8_t *b, *p;

	cga_init();

	if (!cga_ready_to_ver(cga)) {
		applog(LOG_ERR, "%s: CGA context not ready for verification",
		       __FUNCTION__);
		return (-1);
	}
	ws->buf = cga->der;
	ws->dlen = cga->derlen;

	DBG(&dbg_ver, "Verifying address %s",
	    inet_ntop(AF_INET6, &cga->addr, abuf, INET6_ADDRSTRLEN));

	DBG(&dbg_ver, "checking bits on the address");
	if ((cga->addr.s6_addr[8] & 3) != 0) {
		DBG(&dbg_ver, "U &| G bits set");
		return (-1);
	}

	/* Retrieve sec */
	sec = cga_get_sec(&cga->addr);
	DBG(&dbg_ver, "sec is %d", sec);

	DBG_HEXDUMP(&dbg_ver, "DER-encoded data: ", ws->buf,
	    ws->dlen);

	DBG(&dbg_ver, "Parsing DER-encoded data");
	if (cga_parse_params(ws) < 0) {
		return (-1);
	}

	DBG_HEXDUMP(&dbg_ver, "modifier: ", ws->mod, CGA_MODLEN);
	DBG_HEXDUMP(&dbg_ver, "prefix: ", ws->pfx, 8);
	col = *ws->col;
	DBG(&dbg_ver, "collision count: %d", col);

	if (memcmp(ws->pfx, &cga->addr, 8) != 0) {
		DBG(&dbg_ver, "prefix does not match");
		return (-1);
	}
	if (col < 0 || col > CGA_MAX_COL) {
		DBG(&dbg_ver, "collision count out of range");
		return (-1);
	}

	SHA1(ws->buf, ws->dlen, hash);
	DBG_HEXDUMP(&dbg_ver, "hash1: ", hash, 8);

	DBG(&dbg_ver, "--- Setting bits ---");
	setbits(hash, sec);
	/* Ignore sec and U/G bits for comparison */
	memcpy(taddr, &cga->addr.s6_addr[8], 8);
	setbits(taddr, sec);

	if (memcmp(hash, taddr, 8) != 0) {
		DBG(&dbg_ver, "hash1 does not match");
		return (-1);
	}

	/* Dup the DER buf so that we can modify it */
	if ((b = malloc(ws->dlen)) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (-1);
	}
	memcpy(b, ws->buf, ws->dlen);

	/* Zero the prefix */
	p = b + (ws->pfx - ws->buf);
	memset(p, 0, 8);

	/* Zero the collision count */
	p = b + (ws->col - ws->buf);
	*p = 0;

	SHA1(b, ws->dlen, hash);
	DBG_HEXDUMP(&dbg_ver, "hash2: ", hash, CGA_MODLEN * 7 / 8);

	if (cga_cmp(hash, sec * CGA_SECMULT) != 1) {
		DBG(&dbg_ver, "hash2 does not match");
		free(b);
		return (-1);
	}
	free(b);

	DBG(&dbg_ver, "Address verified");
	return (0);
}

int
cga_init(void)
{
	int r = 0;

	pthread_mutex_lock(&initlock);
	if (!cga_initialized) {
		OpenSSL_add_all_algorithms();
		ERR_load_crypto_strings();
#ifdef	APPLOG_DEBUG		
		r = cga_dbg_init();
#endif
		cga_initialized = 1;
	}
	pthread_mutex_unlock(&initlock);

	return (r);
}
