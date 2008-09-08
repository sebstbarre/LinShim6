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

/*
 * A buffered source of randomness. Experiments show that reads to
 * /dev/[u]random can be expensive, so to ensure that time critical
 * operations (such as puzzle-I selection needed to send an R1) are
 * fast, we read instead from a bufer which is populated asynchronously
 * from /dev/urandom by a thread. The thread will refill the buffer
 * whenever more than half the buffer has been read. If you find that
 * on a busy server rand requests outstrip the buffer refilling thread,
 * increase the buffer size.
 * Switch to /dev/random? Need more experience with blocking times...
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <applog.h>
#include <thrpool.h>

#include "os_specific.h"
#include "cgad_local.h"

#define	SND_RAND_BUFSIZ	2048

static uint8_t *rand_buf;
static int rand_off;

static int
fill_rand_buf(void *c)
{
	int fd = open("/dev/urandom", O_RDONLY);

	if (fd < 0) {
		applog(LOG_ERR, "%s: failed to open /dev/urandom: %s",
		       __FUNCTION__, strerror(errno));
		return (-1);
	}

	if (read(fd, rand_buf, SND_RAND_BUFSIZ) < 0) {
		applog(LOG_ERR, "%s: failed to read from /dev/urandom: %s",
		       __FUNCTION__, strerror(errno));
		close(fd);
		return (-1);
	}

	close(fd);
	rand_off = 0;
	return (0);
}

static inline int
start_rand_update(void)
{
	return (thrpool_req((void *)fill_rand_buf, NULL, NULL, 0));
}

/**
 * Gets random bytes.
 *
 * b: a buffer into which to place the random bytes
 * num: number of bytes needed. b must be at least num bytes long.
 *
 * returns 0 on success, -1 on failure
 */
int
os_specific_get_rand_bytes(void *b, int num)
{
	int off = rand_off;
	int r = 0;

	if (num + off >= (SND_RAND_BUFSIZ / 2)) {
		off = rand_off = 0;
		r = start_rand_update();
	}
	rand_off += num;

	memcpy(b, rand_buf + off, num);

	return (r);
}

int
linux_rand_init(void)
{
	if ((rand_buf = malloc(SND_RAND_BUFSIZ)) == NULL) {
		applog(LOG_CRIT, "%s: no memory", __FUNCTION__);
		return (-1);
	}

	return (fill_rand_buf(NULL));
}

void
linux_rand_fini(void)
{
	free(rand_buf);
}
