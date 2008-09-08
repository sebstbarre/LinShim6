/*
 *	Linux shim6 implementation (LinShim6) - daemon part
 *
 *      CGA support (inspired from the DoCoMo SEND implementation)
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : November 2007
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _CGA_PARAMS_H
#define _CGA_PARAMS_H

#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>
#include <list.h>
#include <openssl/sha.h>
#include <netinet/in.h>
#include <hashtbl.h>

struct cga_params;

struct sig_method {
	uint8_t		*(*sign)(struct iovec *, int, int *, void *);
	int		(*verify)(struct iovec *, int, uint8_t *, int,
				  uint8_t *, int);
	void		*(*load_key)(const char *);
	void		(*free_key)(void *);
	int		(*init)(void);
	int		(*params_init)(struct cga_params *);
	void		(*fini)(void);
	uint8_t		type;
	const char	*name;
	struct list_head list;
};

struct cga_params {
	void			*key;
	struct sig_method	*sigmeth;
	uint8_t			*der;
	struct hba_set          *hs;
	int			dlen;
	uint8_t			sec;
	uint8_t			refcnt;
	uint8_t			keyhash[SHA_DIGEST_LENGTH];
};

extern struct list_head hba_sets;

extern int add_addr_params(struct in6_addr *, int, const char *,
			   const char *, int, struct sig_method *, char*);
extern int add_addr_params_use(struct in6_addr *, int, const char *);
extern int add_named_hbaset(const char* name,uint64_t* set, int length);
extern int add_named_params(const char *, const char *, const char *, int,
			    struct sig_method *,char*);
extern int add_named_params_use(const char *, const char *);
extern int del_addr_params(struct in6_addr *, int);
extern int del_named_params(const char *);
extern void dump_params(int fd);
extern struct cga_params *find_params_byaddr(struct in6_addr *, int);
extern struct cga_params *find_params_byifidx(int);
extern void hold_cga_params(struct cga_params *);
extern void put_cga_params(struct cga_params *);
extern int cgad_params_init(void);
extern void cgad_params_fini(void);


/*Defined in params_gram.c (generated based on params_gram.y)*/
extern FILE *params_in;
extern int params_parse(void);

#endif /*_CGA_PARAMS_H*/
