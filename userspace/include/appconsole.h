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

#ifndef	__CONSOLE_H
#define	__CONSOLE_H

#define	CONSOLE_BUFSIZ	128

typedef void (*cons_cmd_handler)(char *);
typedef void (*cons_exit_handler)(void);

typedef struct cons_info {
	const char	*cmdstr;
	const char	*helpstr;
	int		cmdlen;
	cons_cmd_handler cmd_handler;
} cons_info_t;

/* Used often - finds first argument */
#define	APPCONSOLE_FIRST_ARG(__cmd, __setto, __errmsg) \
    do {					\
	__setto = strchr(__cmd, ' ');		\
	if (!(__setto)) {			\
		printf(__errmsg); return;	\
	}					\
	*(__setto)++ = 0;			\
	while (*(__setto) == ' ') (__setto)++;	\
	if (*(__setto) == 0) {			\
		printf(__errmsg); return;	\
	}					\
    } while (0)

#define	APPCONSOLE_NEXT_ARG(__cmd, __setto, __errmsg) \
	APPCONSOLE_FIRST_ARG(__cmd, __setto, __errmsg)

extern void console_exit(void);
extern int console_init(int, int, cons_info_t *, int, cons_exit_handler,
    const char *);
extern void console_read(void);
extern void console_read_char(void);

#endif	/* __CONSOLE_H */
