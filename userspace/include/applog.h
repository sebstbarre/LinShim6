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

#ifndef	__LIB_APPLOG_H
#define	__LIB_APPLOG_H

#include <config.h>
#include <syslog.h>
#include <stdint.h>

#define	LIBLOG_MAX_MASK	2 /* uint32_t's */
#define	LIBLOG_MAX_STACK_DEPTH	20

struct dlog_desc {
	char		*desc;
	char		*ctx;
	uint32_t 	bit[LIBLOG_MAX_MASK];
};

#ifdef	APPLOG_DEBUG

extern uint32_t debug_mask;
extern void dlog(char *format, ...);

#define	DBG(desc, args...) \
	applog_dbg(desc, __FUNCTION__, args)

#define	DBGF(desc, func, args...) \
	applog_dbg(desc, func, args)

#define	DBG_HEXDUMP(desc, msg, buf, len) \
	applog_dhexdump(desc, __FUNCTION__, buf, len, msg)

#define	DBG_STACKTRACE(desc, msg) \
	applog_stacktrace(desc, msg)

#else

#define	DBG(desc, args...)
#define	DBGF(desc, func, args...)
#define	DBG_HEXDUMP(desc, msg, buf, len)
#define	DBG_STACKTRACE(desc, msg)

#endif /*APPLOG_DEBUG*/

/* Convenience macros */
#define	APPLOG_NOMEM()	applog(LOG_CRIT, "%s: no memory", __FUNCTION__)

/*
 * Timestamp functions and macros - they do nothing unless
 * LOG_TIMESTAMP is defined.
 */
#ifdef	LOG_TIMESTAMP

extern int _g_applog_timestamp_nest_level;

#include <sys/time.h>
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

#define	DEFINE_TIMESTAMP_VARS() struct timeval __ts_start[1], __ts_end[1]

#define	TIMESTAMP_START()						\
	do {								\
		_g_applog_timestamp_nest_level++;			\
		gettimeofday(__ts_start, NULL);				\
	} while (0)

#define	TIMESTAMP_END_COMMON(__msg, __start, __end)			\
do {									\
	struct timeval __ts_diff[1];					\
	gettimeofday(__end, NULL);					\
	timersub(__end, __start, __ts_diff);				\
	applog(LOG_INFO, "%-*s%-*s: %-18s %2ld.%.6ld",			\
	       _g_applog_timestamp_nest_level, " ",			\
	       24 - _g_applog_timestamp_nest_level,			\
	       __FUNCTION__,						\
	       __msg,							\
	       __ts_diff->tv_sec, __ts_diff->tv_usec);			\
	_g_applog_timestamp_nest_level--;				\
} while (0)

#define	TIMESTAMP_END(__msg) TIMESTAMP_END_COMMON(__msg, __ts_start, __ts_end)

#define	TIMESTAMP_START_GLOBAL(__ts_gstart) gettimeofday(__ts_gstart, NULL)
#define	TIMESTAMP_END_GLOBAL(__ts_gstart, __msg)			\
do {									\
	struct timeval __ts_end[1];					\
	gettimeofday(__ts_end, NULL);					\
	TIMESTAMP_END_COMMON(__msg, __ts_gstart, __ts_end);		\
} while (0)

#else	/* !LOG_TIMESTAMP */

#define	DEFINE_TIMESTAMP_VARS()
#define	TIMESTAMP_START()
#define	TIMESTAMP_END(__msg)
#define	TIMESTAMP_START_GLOBAL(__ts_gstart)
#define	TIMESTAMP_END_GLOBAL(__msg, __ts_gstart)

#endif	/* LOG_TIMESTAMP */

#define	L_NONE		0
#define	L_STDERR	1
#define	L_SYSLOG	2

extern uint32_t log_all_on[LIBLOG_MAX_MASK];

extern void applog_addlevel(uint32_t *);
extern void applog_clearlevel(uint32_t *);
extern void applog_dbg(struct dlog_desc *, const char *, char *, ...);
extern void applog_printlevels(void);
extern void applog_print_curlevels(void);
extern void applog_dhexdump(struct dlog_desc *, const char *, uint8_t *, int,
    const char *);
extern void applog_stacktrace(struct dlog_desc *, char *);

extern const char *mac2str(uint8_t *, int);
extern const char *mac2str_r(uint8_t *, int, char *buf);
extern int str2mac(const char *, uint8_t *, int *);
extern void applog_hexdump(uint8_t *, int, const char *, const char *);
extern void applog(int prio, char *format, ...);
extern const char **applog_get_methods(void);
extern int applog_str2method(const char *);
extern int applog_open(int, char *);
extern int applog_set_method(int);

extern int applog_register(struct dlog_desc **);
extern int applog_enable_level(const char *, const char *);
extern int applog_disable_level(const char *, const char *);

#endif	/* __LIB_LOG_H */
