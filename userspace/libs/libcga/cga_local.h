/*
 * Now maintained by Sébastien Barré as part of the LinShim6 software
 * Last modified : May 2008
 * Coyright 2008, Université catholique de Louvain
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


/**
 * Private helper functions for CGA. Some like incr_mod and cga_cmp
 * are included here so they can also be accessed by unit tests 
 * or the hba module.
 */

#ifndef	_CGA_LOCAL_H
#define	_CGA_LOCAL_H

#ifndef	timersub
# define timersub(a, b, result)                                               \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)
#endif

static uint8_t cga_nil_cmp[7 * CGA_SECMULT];

/**
 * Increments mod as if it were a CGA_MODLEN * 8 bit number.
 */
static __inline__ void
incr_mod(uint8_t *mod)
{
	int i = CGA_MODLEN - 1;

	/* common case */
	if (mod[i] < 255) {
		mod[i]++;
		return;
	}

	while (i >= 0 && mod[i] == 255) {
		mod[i--] = 0;
	}

	if (i >= 0) {
		mod[i]++;
	}
}

/**
 * Compares the n leftmost bits of b against 0.
 *
 * returns 1 if the bits match, 0 if not.
 */
static __inline__ int
cga_cmp(uint8_t *b, int n)
{
	return (memcmp((uint16_t *)b, cga_nil_cmp, n / (CGA_SECMULT / 2)) == 0);
}

extern void cga_findmod_cancel(void);
extern int cga_findmod_mt(uint32_t, uint8_t *, uint8_t *, int, int, int);
extern uint8_t *cga_get_multikey_key(uint8_t *, int *);
extern uint8_t *cga_parse_key(uint8_t *, int *);
extern int cga_parse_next_ext(uint8_t *, int, int *, uint16_t *);
extern void ssl_err(const char *, const char *);
extern int
cga_init_generation(struct cga_parsed_params *ws, cga_ctx_t *cga);
extern int
find_modifier(cga_ctx_t *cga, struct cga_parsed_params *ws);
extern void setbits(uint8_t *id, uint8_t sec);
void concat(uint64_t *pfx, uint8_t *hash, struct in6_addr *addr);
extern int ws_parse_common(struct cga_parsed_params *ws);
extern int cga_add_multipfx_ext(struct cga_parsed_params *ws, cga_ctx_t *cga);
#ifdef	APPLOG_DEBUG
extern struct dlog_desc dbg_gen, dbg_ver, dbg_asn1, dbg_mt, dbg_ssl, dbg_stats;
extern int cga_dbg_init(void);
#endif

#endif	/* _CGA_LOCAL_H */
