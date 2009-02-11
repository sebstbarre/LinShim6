/*
 * Implementation of the RSASSA-PKCS1-V1_5.c signing algorithm, 
 * defined in RFC2437.
 * 
 * This file comes from the DoCoMo SEND project (sig_rfc3971.c)
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
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include <cga_keyutils.h>

#include <cryptoshim6/sig_RSASSA-PKCS1-v1_5.h>
#include <cryptoshim6/cga_params.h>
#include <cryptoshim6/openssl.h>
#include <cryptoshim6/sigmeth.h>

#include <utils/debug.h>

#ifdef	APPLOG_DEBUG
extern struct dlog_desc dbg_cryptox;

struct dlog_desc dbg_sig = {
	.desc = "sig_RSASSA-PKCS1-v1_5",
	.ctx = "LinShim6"
};
#endif

#define MIN_KEY_BITS 1024

static void *
load_privkey(const char *f)
{
	FILE *fp;
	EVP_PKEY *k;

	if ((fp = fopen(f, "r")) == NULL) {
		applog(LOG_ERR, "%s: fopen '%s' failed: %s", __FUNCTION__,
		       f, strerror(errno));
		return (NULL);
	}

	k = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	if (k == NULL) {
		openssl_err(__FUNCTION__, "PEM_read_PrivateKey failed");
		fclose(fp);
		return (NULL);
	}
	fclose(fp);

	if (EVP_PKEY_bits(k) < MIN_KEY_BITS) {
		DBG(&dbg_sig, "private key too short - %d bits : should be at "
		    "least %d bits",EVP_PKEY_bits(k),MIN_KEY_BITS);
	}

	return (k);
}

static void
free_privkey(void *k)
{
	EVP_PKEY_free(k);
}

/**
 * Caller must free result
 */
static uint8_t *
sign(struct iovec *iov, int iovlen, int *slen, void *priv /* EVP_PKEY */)
{
	EVP_MD_CTX ctx[1];
	uint8_t *sig = NULL;
	DEFINE_TIMESTAMP_VARS();
	int i;

	if (priv == NULL) {
		DBG(&dbg_sig, "private key not set");
		return (NULL);
	}

	if (EVP_PKEY_bits(priv) < MIN_KEY_BITS) {
		DBG(&dbg_sig, "private key too short - %d bits : should be at "
		    "least %d bits",EVP_PKEY_bits(priv),MIN_KEY_BITS);
	}

	if ((*slen = EVP_PKEY_size(priv)) == 0) {
		DBG(&dbg_sig, "EVP_PKEY_size() returned 0");
		return (NULL);
	}

	TIMESTAMP_START();

	EVP_MD_CTX_init(ctx);
	if (EVP_SignInit(ctx, EVP_sha1()) != 1) {
		openssl_err(__FUNCTION__, "EVP_SignInit: ");
		return (NULL);
	}

	for (i = 0; i < iovlen; i++) {
		DBG_HEXDUMP(&dbg_cryptox, "data:", iov[i].iov_base,
			    iov[i].iov_len);

		if (EVP_SignUpdate(ctx, iov[i].iov_base, iov[i].iov_len)
		    != 1) {
			openssl_err(__FUNCTION__, "EVP_SignUpdate: ");
			goto done;
		}
	}

	if ((sig = malloc(*slen)) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		goto done;
	}

	if (EVP_SignFinal(ctx, sig, (unsigned int *)slen, priv) != 1) {
		DBG(&dbg_sig, "sign failed");
		openssl_err(__FUNCTION__, "EVP_SignFinal: ");
		free(sig);
		sig = NULL;
		goto done;
	}

	TIMESTAMP_END("rfc3971");

	DBG_HEXDUMP(&dbg_cryptox, "sig:", sig, *slen);

done:
	EVP_MD_CTX_cleanup(ctx);
	return (sig);
}

static int
ver(struct iovec *iov, int iovlen, uint8_t *key, int klen, uint8_t *sig,
    int slen)
{
	EVP_MD_CTX ctx[1];
	EVP_PKEY *pub;
	int rv = -1;
	int i, real_slen, min_bits;
	DEFINE_TIMESTAMP_VARS();

	DBG_HEXDUMP(&dbg_cryptox, "key: ", key, klen);
	DBG_HEXDUMP(&dbg_cryptox, "sig: ", sig, slen);

	if ((pub = cga_der2key(key, klen)) == NULL) {
		DBG(&dbg_sig, "could not d2i key");
		return (-1);
	}

	min_bits = MIN_KEY_BITS;
	if (EVP_PKEY_bits(pub) < min_bits) {
		syslog(LOG_INFO, "Peer key too weak: %d bits (configured "
		       "minimum: %d)", EVP_PKEY_bits(pub), min_bits);
		return (-1);
	}

	real_slen = EVP_PKEY_size(pub);
	if (real_slen < slen) {
		slen = real_slen;
	} else if (real_slen > slen) {
		DBG(&dbg_sig, "real sig len (%d) > given sig len (%d)",
		    real_slen, slen);
		return (-1);
	}
	TIMESTAMP_START();

	EVP_MD_CTX_init(ctx);
	if (EVP_VerifyInit(ctx, EVP_sha1()) != 1) {
		openssl_err(__FUNCTION__, "EVP_VerifyInit: ");
		return (-1);
	}

	for (i = 0; i < iovlen; i++) {
		DBG_HEXDUMP(&dbg_cryptox, "data: ", iov[i].iov_base,
			    iov[i].iov_len);

		if (EVP_VerifyUpdate(ctx, iov[i].iov_base, iov[i].iov_len)
		    != 1) {
			DBG(&dbg_sig, "verify failed");
			openssl_err(__FUNCTION__, "EVP_VerifyUpdate: ");
			goto done;
		}
	}

	rv = EVP_VerifyFinal(ctx, sig, slen, pub);
	if (rv <= 0) {
		openssl_err(__FUNCTION__, "EVP_VerifyFinal: ");
		rv = -1;
	} else {
		rv = 0;
	}

	TIMESTAMP_END("rfc3971");

done:
	EVP_MD_CTX_cleanup(ctx);
	return (rv);
}

static struct sig_method RSASSA_PKCS1_V1_5_SIGMETH_sig = {
	.sign		= sign,
	.verify		= ver,
	.load_key	= load_privkey,
	.free_key	= free_privkey,
	.name		= RSASSA_PKCS1_V1_5_SIGMETH,
};

void sig_init_RSASSA_PKCS1_V1_5_SIGMETH(void)
{
#ifdef	APPLOG_DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg_sig,
		NULL
	};

	applog_register(dbgs);
#endif
      	register_sig_method(&RSASSA_PKCS1_V1_5_SIGMETH_sig);
}
