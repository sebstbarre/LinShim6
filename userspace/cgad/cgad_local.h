/*
 * Coyright 2008, Université catholique de Louvain
 * Now maintained by Sébastien Barré - sebastien.barre@uclouvain.be
 *  last modified : Feb 2008
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

#ifndef	_CGAD_LOCAL_H
#define	_CGAD_LOCAL_H

#include <config.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <list.h>
#include <sbuff.h>
#include <openssl/sha.h>


#define	CGAD_NAME	"cgad"
#define	CGAD_CONF_FILE	CONFIG_DIR "/cgad.conf"

#define	CGAD_HASH_SZ	7

/* Convenience macro */
#define	ARR_SZ(a)	sizeof (a) / sizeof (*(a))

#define	CGAD_MAX_PKT		2048

/* Infinite lifetime for configuring addresses in the kernel */
#define	CGAD_LIFE_INF		0xffffffff

/* Macros to assist with setting thrpool priorities - higher is better */
#define	CGAD_THR_PRIO_OUT	20
#define	CGAD_THR_PRIO_IN		1
#define	CGAD_THR_PRIO_RESP	10


/* addr.c */
extern int cgad_addr_init(void);
extern int cgad_replace_non_cga_linklocals(void);
extern int cgad_replace_this_non_cga_linklocal(struct in6_addr *, int);
extern int do_replace_address(struct in6_addr *old, struct in6_addr *new, 
			      int ifidx);

/* config.c */
extern int cgad_add_iface(const char *);
extern void cgad_config_fini(void);
extern void cgad_dump_ifaces(void);
extern int cgad_iface_ok(int);
extern int cgad_read_config(char *);

/* net.c */
extern void cgad_icmp_sock_read(void);
extern int cgad_net_init(void);
extern struct sbuff *cgad_get_buf(void);
extern void cgad_put_buf(struct sbuff *);
extern int cgad_send_icmp(struct sbuff *, struct sockaddr_in6 *, int);

/* opt.c */
extern int cgad_add_cga_opt(struct sbuff *, uint8_t *, int);
extern int cgad_add_nonce_opt(struct sbuff *, uint8_t *, int);
extern int cgad_add_timestamp_opt(struct sbuff *);
extern int cgad_add_sig_opt(struct sbuff *, uint8_t *, uint8_t *, int, uint8_t);
extern int cgad_init_opt(void);

/* proto.c */
extern struct cgad_sig_method *cgad_packetinfo_sigmeth(void *);
extern int cgad_proto_init(void);
extern void cgad_proto_fini(void);
extern void cgad_finish_racheck(void *, int);

/* ra.c */
extern int cgad_process_ra(uint8_t *, int, int, struct in6_addr *);
extern int cgad_ra_init(void);
extern void cgad_ra_fini(void);
extern void cgad_verify_ra(uint8_t *, int, int, void *);

/* cgad.c */
extern void cgad_cleanup(void);

#endif	/* _CGAD_LOCAL_H */
