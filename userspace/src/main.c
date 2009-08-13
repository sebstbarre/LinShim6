/*
 *	Linux shim6d daemon  (from the LinShim6 package)
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : May 2008
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <config.h>
#include <shim6/reapd.h>
#include <shim6/shim6d.h>
#include <shim6/tqueue.h>
#include "shim6_rawsocket.h"
#include "pipe.h"
#include "idips.h"
#include "info_server.h"
#include "xfrm.h"

#include <signal.h>
#include <unistd.h>
#include <linux/shim6.h>
#include <linux/shim6_netlink.h>
#include <libnetlink.h>
#include <cryptoshim6/openssl.h>
#include <cryptoshim6/cga.h>
#include <utils/misc.h>
#include <utils/debug.h>

#ifdef DEBUGGING
#include <execinfo.h>
#endif


/*===============*/

/*Data used by shim6eval, and set here to a value that 
 * allows normal behaviour of shim6d*/

int attack=0;

/*================*/

/*Buffer length for ancillary data (IPv6 dest address)*/

#define CMSG_BUF_LEN 128

/*================*/

int bpipe=0; /*1 if there is a pending SIGPIPE signal*/

/*================*/

static void sigterm_handler(int sig)
{
	syslog(LOG_INFO, "caught signal, terminating...\n");
	unlink(LOCALSTATE_DIR "/run/shim6d.pid");
	shim6_del_all_ctx();
	/*Stopping the info server*/
	exit_info_server();
	exit(EXIT_SUCCESS);
}

/*Prints a backtrace and exits*/
static void sigsegv_handler(int sig)
{
	int nptrs,i;
	void *buffer[100];
	char **strings;
	syslog(LOG_ERR, "segmentation fault\n");
	
	/*----- Printing backtrace*/
#ifdef DEBUGGING
	nptrs = backtrace(buffer, sizeof(buffer));
	syslog(LOG_ERR, "backtrace() returned %d addresses\n", nptrs);
	
	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL) {
		perror("backtrace_symbols");
		exit(EXIT_FAILURE);
	}
	
	for (i = 0; i < nptrs; i++)
		syslog(LOG_ERR, "%s\n", strings[i]);
	
	free(strings);
#endif
	/*----- end of backtrace*/
		
	unlink(LOCALSTATE_DIR "/run/shim6d.pid");
	shim6_del_all_ctx();
	/*Stopping the info server*/
	exit_info_server();
	exit(EXIT_FAILURE);
}

/*The sigpipe is received if the info server has a broken stream.
 * the behaviour is to do nothing here. Then the info server writing
 * instruction will stop with errno set to EINTR. Thus skipping each 
 * read/write instruction and finally closing the temporary socket*/
static void sigpipe_handler(int sig)
{
	PDEBUG("Broken pipe\n");
	bpipe=1;
}

int daemonize(void)
{
	pid_t pid,sid;
	int logfd; /*For fatal errors*/
	
	/*Fork off the parent process*/
	pid=fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}
	/* If we got a good PID, then
	   we can exit the parent process. */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}
	
	/*Change the file mode mask*/
	umask(0);

	/*Create a new SID*/
	sid=setsid();
	if (sid<0) {
		syslog(LOG_ERR,"setsid : %m\n");
		goto failure;
	}
	
	 /*Close out the standard file descriptors*/
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	
	/*In case of fatal error during execution, the system may try 
	  to print to standard output. We must redirect this into a log 
	  file. (if not, some socket will get the file descriptor of STDOUT,
	  with the result of the error message being printed inside an IPv6 
	   packet...*/
	mkdir(LOCALSTATE_DIR "/shim6",00750); /*Create shim6 dir if necessary*/
	logfd=open(LOCALSTATE_DIR "/shim6/shim6d.log",
		   O_WRONLY|O_CREAT|O_APPEND,00640);
	if (logfd<0) {
		syslog(LOG_ERR,"open : %m\n");
		goto failure;
	}
	if (dup2(logfd,STDOUT_FILENO)<0 || dup2(logfd,STDERR_FILENO)<0) {
		syslog(LOG_ERR,"dup2 : %m\n");
		goto failure;
	}
	
	close(logfd);
	sanitise_stdfd();
	return 0;
failure:
	return -1;
}

int main(int argc, char* argv[]) {
	
	struct nlmsghdr* nlhdr=NULL;
	struct shim6hdr_ctl* shim6hdr=NULL;
	struct iovec iov_netlink,iov_shim6;
	struct msghdr msg_netlink,msg_shim6;
	struct sockaddr_in6 addr; /*To store the source address of incoming
				    shim6 packets*/
	struct in6_pktinfo* pkt_info; /*To store the dest address of incoming
					shim6 packets*/
	static unsigned char chdr[CMSG_BUF_LEN];
	fd_set fdset; /*To listen to both the netlink and reap sockets*/

	FILE* pidfile; /*file for ../run/shim6d.pid*/
	int ans;
	int pipefd; /*File descriptor for timer notification*/
	int do_daemon=1;
	
	
	while (argc > 1 && (ans = getopt(argc, argv, "f")) != -1) {
		switch (ans) {
		case 'f':
			do_daemon=0;
			break;
		default:
			printf("Usage: %s [-f]\n", argv[0]);
			exit(EXIT_FAILURE);
		}		
	}
	
	if (do_daemon && daemonize()<0) goto failure;
	
	/* Open log */
	openlog("shim6d",0,LOG_DAEMON);
	
	/*Change the current working directory*/
	if ((chdir("/")) < 0) {
		syslog(LOG_ERR,"chdir : %m\n");
		goto failure;
	}
	
	/*Create a shim6d.pid entry in ../run*/
	pidfile = fopen(LOCALSTATE_DIR "/run/shim6d.pid", "w");
	
	if (pidfile == NULL) {
		syslog(LOG_ERR,
		       "Couldn't create pid file \""
		       LOCALSTATE_DIR "/run/shim6d.pid\": "
		       "%m");
	} else {
		fprintf(pidfile, "%ld\n", (long) getpid());
		fclose(pidfile);
	}
	
	/*Create a ../run/shim6 dir if necessary*/
	mkdir(LOCALSTATE_DIR "/run/shim6",00750);
	
	/*register signal handlers*/
	signal(SIGTERM, sigterm_handler);
	signal(SIGQUIT, sigterm_handler);
	signal(SIGSEGV, sigsegv_handler);
	signal(SIGPIPE, sigpipe_handler);
	
	
	/*Initialize the pipe*/
	pipefd=pipe_init();
	if (pipefd<0) {
		syslog(LOG_ERR,"error in pipe_init : %m\n");
		goto failure;
	}
	
	/*Initialize the timer queue*/
	if (taskqueue_init()<0) {
		syslog(LOG_ERR, "error in taskqueue_init : %m\n");
		goto failure;
	}
		
	/*Initialize netlink*/
	if (netlink_init()<0) goto failure;

	/*Initialize OpenSSL*/
	if (openssl_init()<0) {
		syslog(LOG_ERR, "openssl_init\n");
		goto failure;
	};

	/*Enable all applog loglevels if option is set*/
#ifdef APPLOG_DEBUG
	if (applog_open(applog_str2method("syslog"),"LinShim6")<0) {
		syslog(LOG_ERR,"applog_open failed");
		goto failure;
	}
	applog_addlevel(log_all_on);
#endif


	/*Initialize CGA*/

	if (shim6_cga_init()<0) {
		syslog(LOG_ERR, "shim6_cga_init : %m\n");
		goto failure;
	}
	
	if (cgad_params_init()<0) {
		syslog(LOG_ERR, "cgad_params_init : %m\n");
		goto failure;
	}
	
	/*Initialize xfrm*/
	if (xfrm_init()<0) {
		syslog(LOG_ERR, "A problem occured during xfrm_init\n");
		goto failure;
	}
	
	/*Initialize IDIPS*/
#ifdef IDIPS
	if (idips_init<0) {
		syslog(LOG_ERR, "A problem occured during idips_init\n");
		goto failure;
	}
#endif

	PDEBUG("Initializing shim6\n");
	
	if (shim6d_init()<0) goto failure;
	
	PDEBUG("Initializing REAP\n");
	
	if (reapd_init()<0) goto failure;
	
	
	/*Preparing the structures for message reception from the kernel*/
	if (netlink_alloc_rcv(MAX_NL_PAYLOAD, &nlhdr, &msg_netlink,
			      &iov_netlink)<0) {
		syslog(LOG_ERR, "netlink_alloc_rcv failed\n");
		goto failure;
	}
	
	/*Initialize raw sockets*/
	if (shim6_rawsocket_init()<0) {
		syslog(LOG_ERR,"shim6_rawsocket_init failed\n");
		goto failure;
	}
	
	/*Initialize info server*/
	if (init_info_server()<0) {
		syslog(LOG_ERR,"init_info_server failed : %m\n");
		goto failure;
	}

	shim6hdr=malloc(MAX_CTL_LEN);
	if (!shim6hdr) {
		syslog(LOG_ERR, "malloc failed\n");
		goto failure;
	}
	
	iov_shim6.iov_base=(void*)shim6hdr;
	iov_shim6.iov_len=MAX_CTL_LEN;
	memset(&msg_shim6,0,sizeof(msg_shim6));
	msg_shim6.msg_name = (void *)&addr;
	msg_shim6.msg_namelen = sizeof(struct sockaddr_in6);
	msg_shim6.msg_iov=&iov_shim6;
	msg_shim6.msg_iovlen=1;
	msg_shim6.msg_control = (void *)chdr;
	msg_shim6.msg_controllen = CMSG_BUF_LEN;
	
	while(1) {
		/*Wait for incoming messages or timer notifications*/
		/*Prepare the data for select*/
		FD_ZERO(&fdset);
		FD_SET(nlsd,&fdset);
		FD_SET(shim6sd_rcv,&fdset);
		FD_SET(pipefd,&fdset);
		
		ans=select(max(pipefd,max(nlsd,shim6sd_rcv))+1,
			   &fdset,NULL,NULL,NULL);
		
		if (ans<0) {
			if (errno==EINTR) continue;
			syslog(LOG_ERR, "select: %m\n");
			goto failure;
		}
		
		if (FD_ISSET(nlsd,&fdset)) {
			PDEBUG("recvd netlink message\n");
			if (recvmsg(nlsd,&msg_netlink,0)<0) {
				syslog(LOG_ERR, "recvmsg : %m\n");
				continue;
			}
			switch(nlhdr->nlmsg_type) {
			case SHIM6_NL_NEW_CTX:
				PDEBUG("Request to create a new shim6 "
				       "context\n");
				init_shim6_ctx(nlhdr);
				break;
			case SHIM6_NL_NEW_LOC_ADDR:
				shim6_new_loc_addr(nlhdr);
				break;
			case SHIM6_NL_DEL_LOC_ADDR:
				shim6_del_loc_addr(nlhdr);
				break;
			case REAP_NL_START_EXPLORE:
				reap_init_explore_kern(nlhdr);
				break;
			case REAP_NL_NOTIFY_IN:
				reap_notify_in(nlhdr);
				break;
			case REAP_NL_NOTIFY_OUT:
				reap_notify_out(nlhdr);
				break;
			case REAP_NL_ART:
				reap_art(nlhdr);
				break;
			case REAP_NL_SEND_KA:
				reap_send_ka(nlhdr);
				break;				 
			}
		}
		if (FD_ISSET(shim6sd_rcv,&fdset)) {
			PDEBUG("recvd shim6 control message\n");
			if (recvmsg(shim6sd_rcv,&msg_shim6,0)<0) {
				syslog(LOG_ERR, "recvmsg : %m\n");
				continue;
			}
			if (get_pkt_info(&msg_shim6, &pkt_info)<0) {
				syslog(LOG_ERR,"get_pkt_info : %m\n");
				 continue;
			}
			
			switch(shim6hdr->type) {
			case REAP_TYPE_PROBE:
				reap_rcv_probe((struct reaphdr_probe*)
					       shim6hdr);
				break;
			case REAP_TYPE_KEEPALIVE:
				reap_rcv_ka((struct reaphdr_ka*)
					    shim6hdr);
				break;
			case SHIM6_TYPE_I1:		
				rcv_i1((shim6hdr_i1*) shim6hdr,&addr.sin6_addr,
				        &pkt_info->ipi6_addr);
				break;
			case SHIM6_TYPE_I2:
				rcv_i2((shim6hdr_i2*) shim6hdr,&addr.sin6_addr,
				       &pkt_info->ipi6_addr, 
				       pkt_info->ipi6_ifindex);
				break;
			case SHIM6_TYPE_I2BIS:
				rcv_i2bis((shim6hdr_i2bis*) shim6hdr,
					  &addr.sin6_addr,
					  &pkt_info->ipi6_addr, 
					  pkt_info->ipi6_ifindex);
				break;
			case SHIM6_TYPE_R1:
				rcv_r1((shim6hdr_r1*) shim6hdr,&addr.sin6_addr,
					&pkt_info->ipi6_addr);
				break;
			case SHIM6_TYPE_R1BIS:
				rcv_r1bis((shim6hdr_r1bis*) shim6hdr,
					  &addr.sin6_addr,
					  &pkt_info->ipi6_addr);
				break;				
			case SHIM6_TYPE_R2:
				rcv_r2((shim6hdr_r2*) shim6hdr,&addr.sin6_addr,
				       &pkt_info->ipi6_addr);
				break;
			case SHIM6_TYPE_UPD_REQ:
				rcv_ur((shim6hdr_ur*) shim6hdr,&addr.sin6_addr,
				       &pkt_info->ipi6_addr);
				break;				 
			case SHIM6_TYPE_UPD_ACK:
				rcv_ua((shim6hdr_ur*) shim6hdr,&addr.sin6_addr,
				       &pkt_info->ipi6_addr);
				break;				 
			}
		}
		if (FD_ISSET(pipefd,&fdset)) {
			pipe_run_handler();		       
		}
	}
	
failure:	 
	 if (shim6hdr) free(shim6hdr);
	 if (nlhdr) free(nlhdr);
	 if (nlsd!=-1) close(nlsd);
	 closelog();
	 exit(EXIT_FAILURE);
}
