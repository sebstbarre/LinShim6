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

#ifndef	_CGA_H
#define	_CGA_H

#include <string.h>
#include <netinet/in.h>
#include <cryptoshim6/cga.h>

#define	CGA_MODLEN	16
#define	CGA_SECMULT	16	/* sec multiplier */
#define	CGA_PARAM_LEN	(CGA_MODLEN + 8 + 1)
#define	CGA_MAX_COL	2
#define	CGA_MAX_SEC	7

struct cga_pseudo {
	uint8_t		msgtype[16];
	struct in6_addr	src;
	struct in6_addr	dst;
} __attribute__ ((packed));

typedef struct {
	/* public members; access directly */
	uint8_t		*key;	/* DER-encoded Public key */
	int		klen;

	struct in6_addr	prefix;	/* Prefix */
	struct in6_addr	addr;	/* CGA Generated address */

	int		collisions; /* Collision count */
	uint8_t		sec;	/* Sec value */
	int		thrcnt;	/* Number of threads to use for generation */
	uint32_t	batchsize; /* work chunk size for each thread */

	/* private members; use accessor functions to modify */
	int		derlen;	/* Length of der, in bytes */
	uint8_t		*der;	/* DER-encoded key and CGA parameters */
	uint8_t		modifier[CGA_MODLEN]; /* Modifier */
	uint16_t
			key_set : 1,
		        prefix_set : 1, /*For CGA*/
		        prefixes_set : 1, /*For HBA*/
		        mod_set : 1,
		        mod_final :1, /*1 if the modifier is the final one 
					(not a rand number)*/
			der_set : 1,
			addr_set : 1,
			free_der : 1,
		        free_key : 1,
		        pseudo_key : 1, /*1 if the key is a pseudo-key 
					  (for HBA)*/
		        is_hba_ctx : 1;
	struct hba_set* hba_data;
} cga_ctx_t;

struct cga_ext_hdr {
	uint16_t	type;
	uint16_t	len;
} __attribute__ ((packed));

/* Multi-key extension type definition */

#define	CGA_MULTIKEY_EXT	1
#define CGA_MULTIPFX_EXT        0x12

struct cga_multikey_ext {
	struct cga_ext_hdr hdr;
	uint16_t	klen;
	uint8_t		key[0];
}  __attribute__ ((packed));

struct cga_multipfx_ext {
	struct cga_ext_hdr hdr;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint32_t    reserved:31,
		    P:1; /*Set if a public key is included in the key field*/
#elif defined(__BIG_ENDIAN_BITFIELD)
	uint32_t    P:1, /*Set if a public key is included in the key field*/
		    reserved:31;
#else
#error	"Unknown endianness : The configure script did not run correctly"
#endif
	uint64_t pfxs[0];
} __attribute__ ((packed));


typedef struct cga_parsed_params {
	uint8_t                   *buf;
	uint8_t	                  *mod;
	uint8_t                   *pfx;
	uint8_t                   *col;
	uint8_t                   *key;
	int                       dlen;
	int                       klen;
	struct cga_multipfx_ext   *mpe;
} cga_parsed_params_t;

#define	cga_init_ctx(__ctx) \
	do { \
		memset(__ctx, 0, sizeof (*__ctx)); \
		__ctx->batchsize = 500000; \
		__ctx->thrcnt = 1; \
	} while (0)

#define	cga_ready_to_gen(__ctx)					\
	((__ctx)->key_set &&					\
	 ((!(__ctx)->is_hba_ctx && (__ctx)->prefix_set) ||	\
	  ((__ctx)->is_hba_ctx && (__ctx)->prefixes_set)))

#define	cga_ready_to_ver(__ctx) \
	((__ctx)->der_set && (__ctx)->addr_set)

#define	cga_get_sec(__a) (((__a)->s6_addr[8] & 0xe0) >> 5)

extern void cga_cleanup_ctx(cga_ctx_t *);
extern void cga_free_ctx(cga_ctx_t *);
extern int cga_generate(cga_ctx_t *);
extern void cga_gen_cancel(void);
extern int cga_verify(cga_ctx_t *);
extern cga_ctx_t *new_cga_ctx(void);
extern int cga_parse_params(struct cga_parsed_params *);
extern int cga_parse_params_ctx(cga_ctx_t *);
extern int cga_init(void);
/**
 * Validates the cga context, by verifying consistency between the der and
 * and the encoded parameters. Returns 0 in case of success, or a negative
 * error code if any inconsistency is found.
 *
 * This function is not necessary for the security, but it is highly useful 
 * to indicate misconfigurations from the user.
 */
extern int cga_validate_ctx(cga_ctx_t* cga);

/*HBA-specific functions*/
extern int hba_generate(cga_ctx_t *hba);
extern int hba_autogen_mpe(cga_ctx_t* hba);
int
hba_set_pseudo(cga_ctx_t* hba, unsigned char *pseudo, unsigned int len);

/* accessors */
extern int cga_set_der(cga_ctx_t *, uint8_t *, int);
extern uint8_t *cga_get_der(cga_ctx_t *, int *);
extern void cga_set_modifier(cga_ctx_t *, uint8_t *);
extern void cga_set_modifier_start(cga_ctx_t *ctx, uint8_t *mod);
extern uint8_t *cga_get_modifier(cga_ctx_t *);
extern void cga_set_addr(cga_ctx_t *, struct in6_addr *);
extern void cga_set_prefix(cga_ctx_t *, struct in6_addr *);
extern int cga_set_sec(cga_ctx_t *, int);
extern int cga_set_col(cga_ctx_t *, int);

/*HBA-specific accessors*/
extern int hba_set_prefixes(cga_ctx_t *hba, struct hba_set* hs);
extern struct hba_set* new_hbaset_pfx(const char* name, uint64_t* set,
				      int length);

extern const char *cga_version;

/*Tools*/

/**
 * Gets random bytes.
 *
 * b: a buffer into which to place the random bytes
 * num: number of bytes needed. b must be at least num bytes long.
 *
 * returns 0 on success, -1 on failure
 */
int
get_rand_bytes(uint8_t *b, int num);

#endif	/* _CGA_H */
/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
