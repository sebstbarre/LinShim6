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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#ifdef	USE_READLINE
#include <pthread.h>
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "appconsole.h"

static cons_info_t *cmds;
static int cmd_cnt;
static FILE *infile, *outfile;
cons_exit_handler exit_handler;
static const char *cons_prompt;

#ifdef	THREADS
static pthread_t cons_tid;
#endif

static void
dohelp(void)
{
	int i;

	for (i = 0; i < cmd_cnt; i++) {
		fprintf(outfile, "%s\t%s\n", cmds[i].cmdstr, cmds[i].helpstr);
	}
	fprintf(outfile, "? help\tShows help\n");
}

static void
docmd(char *buf)
{
	int i;

	if (*buf == 0 || *buf == '\n') {
		return;
	}
	if (*buf == '?' || strncasecmp(buf, "help", 4) == 0) {
		dohelp();
		return;
	}

	for (i = 0; i < cmd_cnt; i++) {
		if (strncasecmp(cmds[i].cmdstr, buf, cmds[i].cmdlen) == 0) {
			cmds[i].cmd_handler(buf);
			return;
		}
	}

	fprintf(outfile, "Unknown command\n");
	return;
}

void
console_read(void)
{
	char buf[CONSOLE_BUFSIZ], *cp;

	if ((cp = fgets(buf, CONSOLE_BUFSIZ, infile)) == NULL) {
		exit_handler();
		return;
	}

	docmd(cp);
	fprintf(outfile, "%s", cons_prompt);
	fflush(outfile);
}

#ifdef	USE_READLINE
static void
handle_rlinput(char *rd)
{
	if (rd == NULL) {
		exit_handler();
#if RL_VERSION_MAJOR >= 4
		rl_cleanup_after_signal();
#endif
		rl_reset_terminal(NULL);
#ifdef	THREADS
		pthread_exit(NULL);
#else
		exit(0);
#endif
	}
	if (*rd != 0) {
		add_history(rd);
	}
	docmd(rd);
	free(rd);
}

#ifdef	THREADS
static void *
console_thr(void *a)
{
	char *rd;

	for (;;) {
		rd = readline(cons_prompt);
		handle_rlinput(rd);
	}

	return (NULL);
}
#endif	/* THREADS */

static char *
possible_cmds(const char *text, int state)
{
	static int len, idx;

	if (state == 0) {
		idx = 0;
		len = strlen(text);
	}

	for (; idx < cmd_cnt; idx++) {
		if (strncmp(cmds[idx].cmdstr, text, len) == 0) {
			return (strdup(cmds[idx++].cmdstr));
		}
	}

	return (NULL);
}
#endif

void
console_read_char(void)
{
#ifdef	USE_READLINE
	rl_callback_read_char();
#endif
}

int
console_init(int infd, int outfd, cons_info_t *ci, int cnt,
    cons_exit_handler exitcb, const char *prompt)
{
	if (cmds != NULL) {
		return (-1);
	}
	cmds = ci;
	cmd_cnt = cnt;
	exit_handler = exitcb;
	cons_prompt = prompt;

	infile = infd == 0 ? stdin : fdopen(infd, "r");
	outfile = outfd == 1 ? stdout : fdopen(outfd, "w");

#ifdef	USE_READLINE
	rl_instream = infile;
	rl_outstream = outfile;
	rl_completion_entry_function = possible_cmds;
#ifdef	THREADS
	if (pthread_create(&cons_tid, NULL, console_thr, NULL) != 0) {
		return (-1);
	}
#else
	rl_callback_handler_install(prompt, handle_rlinput);
#endif	/* THREADS */
#else
	fprintf(outfile, "%s", prompt);
	fflush(outfile);
#endif	/* USE_READLINE */

	return (0);
}

void
console_exit(void)
{
#ifdef	USE_READLINE
#if RL_VERSION_MAJOR >= 4
	rl_cleanup_after_signal();
#endif
	rl_reset_terminal(NULL);
#endif
}
