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
 * Most CGA ASN1-related functions are here. These rely heavily on
 * OpenSSL ASN1 macros.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "config.h"
#include <applog.h>

#include <cga.h>
#include <cga_keyutils.h>
#include "cga_local.h"

/**
 * Loads a certificate from a file and sets its key into the CGA context.
 *
 * cga: the CGA context
 * f: the file name
 *
 * returns 0 on success, -1 on failure
 */
int
cga_load_cert(cga_ctx_t *cga, const char *f)
{
	X509 *x;
	FILE *fp;
	EVP_PKEY *k;
	int r;

	if ((fp = fopen(f, "r")) == NULL) {
		DBG(&dbg_ssl, "fopen failed: %s", strerror(errno));
		return (-1);
	}

	x = PEM_read_X509(fp, NULL, NULL, NULL);
	if (x == NULL) {
		ssl_err(__FUNCTION__, "PEM_read_x509 failed");
		goto fail;
	}

	k = X509_PUBKEY_get(x->cert_info->key);

	if (cga->key && cga->free_key) {
		free(cga->key);
		cga->key = NULL;
	}
	if ((cga->key = cga_key2der(k, &cga->klen)) == NULL) {
		goto fail;
	}
	cga->free_key = 1;
	cga->key_set = 1;

	r = 0;
	goto done;

fail:
	r = -1;
	if (cga->key) free(cga->key);
	cga->key = NULL;
	cga->klen = 0;

done:
	fclose(fp);
	X509_free(x);

	return (r);
}

int
cga_load_key(cga_ctx_t *cga, const char *f)
{
	FILE *fp;
	EVP_PKEY *k = NULL;
	int r = 0;
	int first = 1;
	struct stat sb[1];

	if (stat(f, sb)  < 0) {
		DBG(&dbg_ssl, "Could not stat file: %s\n", strerror(errno));
		return (-1);
	}
	if ((fp = fopen(f, "r")) == NULL) {
		DBG(&dbg_ssl, "Could not open file: %s\n", strerror(errno));
		return (-1);
	}

	if (cga->key && cga->free_key) {
		free(cga->key);
	}
	cga->key = NULL;
	cga->klen = 0;

	while (ftell(fp) < sb->st_size) {
		if ((k = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
			ssl_err(__FUNCTION__, "PEM_read_PrivateKey");
			r = -1;
			break;
		}

		if (cga_add_key(cga, k, first, CGA_MULTIKEY_EXT) < 0) {
			EVP_PKEY_free(k);
			r = -1;
			break;
		}
		first = 0;

		EVP_PKEY_free(k);
	}

	fclose(fp);
	return (r);
}

EVP_PKEY *
cga_der2key(uint8_t *dk, int klen)
{
	EVP_PKEY *k;
	X509_PUBKEY *xpk;

	if ((xpk = d2i_X509_PUBKEY(NULL,
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
				   (const unsigned char **)
#endif
				   &dk, klen))
	    == NULL) {
		applog(LOG_ERR, "%s: d2i failed", __FUNCTION__);
		return (NULL);
	}
	k = X509_PUBKEY_get(xpk);
	X509_PUBKEY_free(xpk);

	return (k);
}

uint8_t *
cga_key2der(EVP_PKEY *k, int *dlen)
{
	uint8_t *p;
	uint8_t *der = NULL;
	X509_PUBKEY *pki = NULL;
	
	if (X509_PUBKEY_set(&pki, k) == 0) {
		ssl_err(__FUNCTION__, "X509_PUBKEY_set() failed");
		goto done;
	}

	if ((*dlen = i2d_X509_PUBKEY(pki, NULL)) < 0) {
		ssl_err(__FUNCTION__, "i2d_PublicKey failed");
		goto done;
	}
	if ((der = malloc(*dlen)) == NULL) {
		APPLOG_NOMEM();
		goto done;
	}

	p = der;
	if (i2d_X509_PUBKEY(pki, &p) < 0) {
		ssl_err(__FUNCTION__, "i2d_PublicKey failed");
		free(der);
		der = NULL;
	}
	DBG(&dbg_asn1, "DER-encoded key is %d bytes", *dlen);

done:
	if (pki) X509_PUBKEY_free(pki);
	return (der);
}

int
cga_set_key(cga_ctx_t *cga, EVP_PKEY *k)
{
	return (cga_add_key(cga, k, 1, 0));
}

void
cga_free_keystack(STACK *sk)
{
	EVP_PKEY *k;

	while ((k = (EVP_PKEY *)sk_pop(sk)) != NULL) {
		EVP_PKEY_free(k);
	}
	sk_free(sk);
}

/*
 * der points to the start of one or more DER-encoded keys. If there is
 * more than one key, the keys must be contained in multi-key CGA
 * extensions.
 *
 * Returns a stack of EVP_PKEYs on success.
 */
STACK *
cga_der2keys(uint8_t *der, int dlen)
{
	uint8_t *dk;
	EVP_PKEY *k;
	int klen, elen;
	uint16_t type;
	STACK *sk;

	if ((sk = sk_new_null()) == NULL) {
		APPLOG_NOMEM();
		return (NULL);
	}

	/* Extract first key, not in an extension */
	dk = cga_parse_key(der, &klen);
	DBG(&dbg_asn1, "getting key 1 (klen %d dlen %d)", klen, dlen);

	if ((k = cga_der2key(der, klen)) == NULL) {
		goto fail;
	}
	if (sk_push(sk, (void *)k) == 0) {
		APPLOG_NOMEM();
		goto fail;
	}

	/* Extract any keys in extensions */
	der += klen;
	dlen -= klen;
	while (dlen > 0) {
		if (cga_parse_next_ext(der, dlen, &elen, &type) < 0) {
			goto fail;
		}
		DBG(&dbg_asn1, "got extension type %d len %d", type, elen);
		if (dlen < elen) {
			DBG(&dbg_asn1, "elen > dlen (%d / %d)", elen, dlen);
			goto fail;
		}
		if (type != CGA_MULTIKEY_EXT) {
			goto next;
		}

		dk = cga_get_multikey_key(der, &klen);
		DBG(&dbg_asn1, "getting ext key (%d bytes)", klen);
		if ((k = cga_der2key(dk, klen)) == NULL) {
			goto fail;
		}
		if (sk_insert(sk, (void *)k, 0) == 0) {
			APPLOG_NOMEM();
			goto fail;
		}

	next:
		dlen -= elen;
		der += elen;
	}

	return (sk);

fail:
	cga_free_keystack(sk);
	return (NULL);
}
