/*
 *	HBA implementation.
 *
 *      This implementation uses the CGA framework from DoCoMo SEND impl.
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : April 2008
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <config.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <openssl/x509.h>

#include <applog.h>
#include <cga.h>
#include "cga_local.h"

/**
 * Creates a new hba set and returns a pointer to it.
 * Returns NULL if there was not enough memory.
 */
struct hba_set* new_hbaset_pfx(const char* name, uint64_t* set,
			       int length)
{
	struct hba_set* s;
	if ((s=malloc(sizeof(*s)))==NULL) {
		APPLOG_NOMEM();
		return NULL;
	}
	bzero(s,sizeof(*s));		
	s->name=name;
	s->set_pfx=set;
	s->length=length;
	return s;
}

/**
 * Stores the pfxs pointer in the structure @hba. Thus the memory allocated
 * for @pfxs cannot be freed if @hba is still using it.
 */
int hba_set_prefixes(cga_ctx_t *hba, struct hba_set* hs)
{
	hba->hba_data=hs; 
      	hba->prefixes_set=1;
	return 0;
}

/* set a pseudo public key */

int
hba_set_pseudo(cga_ctx_t* hba, unsigned char *pseudo, unsigned int len)
{
	X509_PUBKEY *pubkey;
	ASN1_OBJECT *obj;
	unsigned char *p = NULL;
	int dlen=1;

	/* sanity */
	if ((hba == NULL) || (pseudo == NULL))
		return -1;

	/* free previous one */
	if (hba->key_set && hba->free_key)
		free(hba->key);
	hba->key = NULL;
	hba->key_set=0;
	hba->klen = 0;

	/* fill the public key structure */
	pubkey = X509_PUBKEY_new();
	if (pubkey == NULL)
		return -1;
	obj = OBJ_nid2obj(NID_rsaEncryption);
	if (obj == NULL)
		goto bad;
	ASN1_OBJECT_free(pubkey->algor->algorithm);
	pubkey->algor->algorithm = obj;
	if ((pubkey->algor->parameter == NULL) ||
	    (pubkey->algor->parameter->type != V_ASN1_NULL)) {
		ASN1_TYPE_free(pubkey->algor->parameter);
		pubkey->algor->parameter = ASN1_TYPE_new();
		pubkey->algor->parameter->type = V_ASN1_NULL;
	}
	if (!ASN1_BIT_STRING_set(pubkey->public_key, pseudo, len))
		goto bad;
	pubkey->public_key->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
	pubkey->public_key->flags |= ASN1_STRING_FLAG_BITS_LEFT;

	/* get the whole encoding */
	dlen = i2d_X509_PUBKEY(pubkey, &p);
	applog(LOG_DEBUG,"DER pseudo-key generated, length : %d",dlen);
	DBG_HEXDUMP(&dbg_ver, "DER-encoded pseudo-key: ", p,
		    dlen);

	if (dlen <= 0) {
	bad:
		X509_PUBKEY_free(pubkey);
		return -1;
	}

	/* store it */
	hba->key = malloc(dlen);
	if (!hba->key) {
		OPENSSL_free(p);
		X509_PUBKEY_free(pubkey);
		return -1;
	}
	memcpy(hba->key,p,dlen);
	OPENSSL_free(p);		
	hba->klen = (unsigned int)dlen;
	hba->key_set=1;
	hba->pseudo_key=1;

	X509_PUBKEY_free(pubkey);
	return 0;
}


/**
 *  Checks if a multiprefix extension exists for that context.
 *  If it doesn't, it is automatically generated.
 * @post : if the mpe is not in the der, it is added.
 *         hba->der and hba->dlen are adapted accordingly.
 */
int hba_autogen_mpe(cga_ctx_t* hba)
{
	struct cga_parsed_params ws[1];
	bzero(ws, sizeof (*ws));
	ws->buf=hba->der;
	ws->dlen=hba->derlen;
	if (ws_parse_common(ws) < 0) {
		applog(LOG_ERR,"%s:ws_parse_common failed",__FUNCTION__);
		return -1;
	}
	if (ws->mpe) return 0;
	
	if (cga_add_multipfx_ext(ws,hba)<0) return -1;

	return 0;
}

/**
 * Generates a new set of addresses from the parameter set in the CGA context.
 * See the API documentation for more information on how to set these
 * parameters.
 *
 * @pre : - @hba must not be NULL
 *        - @hba->hba_data points to a valid hba_set structure containing
 *          prefixes (not addresses)
 * @post : @hba->hba_data points to a newly allocated hba_set containing 
 *         the generated addresses. The previous value of the pointer is 
 *         NOT freed, however.
 * returns 0 on success, -1 on failure. On success, the new addresses are
 * in the hba->hba_data member. Memory is allocated to store those addresses, 
 * thus the caller is responsible for freeing that memory later.
 *
 */
int
hba_generate(cga_ctx_t *hba)
{	
	struct cga_parsed_params ws[1];
	uint8_t hash[SHA_DIGEST_LENGTH];
	int i;
	struct hba_set* hs_pfx=hba->hba_data;

	if (!cga_ready_to_gen(hba)) {
		applog(LOG_ERR, "%s: HBA context not ready for generation",
		       __FUNCTION__);
		return (-1);
	}

	if (hs_pfx->computed) {
		applog(LOG_ERR,"%s: addresses already generated",__FUNCTION__);
		return -1;
	}

	cga_init();

	memset(ws, 0, sizeof (*ws));

	hba->is_hba_ctx=1;
	
	/*init and Multi-prefix extension generation (step 1)*/
	if (cga_init_generation(ws, hba) < 0) {
		applog(LOG_ERR,"%s: cga_init_generation failed",__FUNCTION__);
		return (-1);
	}
	
	if (hba->collisions > 0) {
		if (hba->collisions > 3) {
			applog(LOG_CRIT, "%s: collisions > 3; "
			    "we may be under attack", __FUNCTION__);
			return (-1);
		}

		DBG(&dbg_gen, "collisions > 0, jumping to hash1");
		memcpy(ws->mod, hba->modifier, CGA_MODLEN);
		goto hash1;
	}
	
	/*Modifier generation (step 2,3,4)*/
	if (!hba->mod_set || !hba->mod_final) {
		DBG(&dbg_gen, "--- Finding modifier ---");
		
		if (find_modifier(hba, ws) < 0) {
			return (-1);
		}
	} else {
		DBG_HEXDUMP(&dbg_gen, "--- Using Modifier ---",
			    hba->modifier, CGA_MODLEN);
		memcpy(ws->mod, hba->modifier, CGA_MODLEN);
	}

hash1:

	if (!(hba->hba_data=
	      malloc(sizeof(struct hba_set)))) {
		APPLOG_NOMEM();
		return -1;
	}
	
	/*Initially this is a copy of the other structure*/
	memcpy(hba->hba_data,hs_pfx,sizeof(*hs_pfx));

	if (!(hba->hba_data->set_addr=
	      malloc(hs_pfx->length*sizeof(struct in6_addr)))) {
		APPLOG_NOMEM();
		return -1;
	}
	      
	for (i=0;i<hs_pfx->length;i++) {

		memcpy(ws->pfx, &hs_pfx->set_pfx[i], 8);
		*(ws->col) = hba->collisions;
		
		DBG_HEXDUMP(&dbg_gen, "Input to hash1:", ws->buf, ws->dlen);
		
		SHA1(ws->buf, ws->dlen, hash);
		
		DBG_HEXDUMP(&dbg_ver, "Output of hash1: ", hash, 8);
		
		DBG(&dbg_gen, "--- Setting bits ---");
		
		setbits(hash, hba->sec);
		
		DBG(&dbg_gen, "--- Concatenating prefix and eui64 ---");
		
		concat(&hs_pfx->set_pfx[i], hash, &hba->hba_data->set_addr[i]);
		hba->der_set = 1;		
	}

	hba->addr_set = 1;
	hba->hba_data->computed=1;

	return (0);
}
