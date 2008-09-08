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

#ifndef	_CGAD_CONFIG_H
#define	_CGAD_CONFIG_H

#include <config.h>

/* Configurables */
enum cgad_conf_syms {
	cgad_addr_autoconf,
	cgad_adv_nonce_cache_life,
	cga_minsec,
	cga_params,
	min_key_bits,
	cgad_nonce_cache_gc_intvl,
	cgad_pfx_cache_gc_intvl,
	replace_linklocal_addresses,
	cgad_sol_nonce_cache_life,
	cgad_timestamp_cache_gc_intvl,
	cgad_timestamp_cache_life,
	cgad_timestamp_cache_max,
	cgad_timestamp_delta,
	cgad_timestamp_drift,
	cgad_timestamp_fuzz,
#ifndef	NOTHREADS
	cgad_thrpool_max,
#endif
#ifdef	APPLOG_DEBUG
	cgad_debugs,
#endif
};

enum cgad_conf_parse {
	CGAD_CONF_P_INT,
	CGAD_CONF_P_STR,
	CGAD_CONF_P_BOOL,
};

struct cgad_conf {
	const char		*sym;
	union {
		const char	*v_str;
		int		v_int;
	} tu;
	const char		*units;
	enum cgad_conf_parse	parse;
	int			mandatory;
	enum cgad_conf_parse	type;
};

extern struct cgad_conf cgad_confs[];

#define	cgad_conf_get_int(_sym) (cgad_confs[_sym].tu.v_int)
#define	cgad_conf_get_str(_sym) (cgad_confs[_sym].tu.v_str)

#endif	/* _CGAD_CONFIG_H */
