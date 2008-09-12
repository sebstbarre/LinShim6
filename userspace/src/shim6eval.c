/*
 *	LinShim6 Measurement module
 *      That program tries to establish many contexts, in order
 *      to perform quantitative measurements on that implementation.
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : June 2008
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
#include <utils/util.h>
#include "shim6_rawsocket.h"
#include "pipe.h"
#include "idips.h"
#include "info_server.h"
#include "xfrm.h"
#include "shim6_local.h"
#include "opt.h"
#include "testparams.h"

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/shim6.h>
#include <linux/shim6_netlink.h>
#include <libnetlink.h>
#include <cryptoshim6/openssl.h>
#include <cryptoshim6/cga.h>
#include <utils/misc.h>
#include <utils/debug.h>

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

static void sigsegv_handler(int sig)
{
	syslog(LOG_ERR, "segmentation fault\n");
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


/*===========================================*/

/*SPECIFIC CODE FOR MEASUREMENTS*/

static struct in6_addr ulid_peer,ulid_peer2;

struct timespec start; /*Time of start for a measurement*/
int measure_sec=0;
int server_mode; /*1 if server mode, 0 if client mode*/
int naddrs; 
int eval_started=0;
int nooptcache=0;
int sequential; /*If 1, measurements are made sequentially, 
		  if 0, they are done in parallel, with one new
		  negotiation every 50 ms.*/
int attack=0;
int eval_counter=0;
struct tq_elem eval_timer;

static const struct timespec EVAL_RENEG = {
	.tv_sec=0,
	.tv_nsec=PARALLEL_TIME*TIME_MSEC_NSEC};

#define NB_PEER_ULIDS 2 /*Currently only support for two ulids at the peer used
			  in the attack*/
#define NB_EVAL_CGAS NB_PARALLEL/NB_PEER_ULIDS /*DO NOT CHANGE*/
struct parameters params[NB_EVAL_CGAS];


/*Defining some loc just used to enter in the signing process,
  It needs not be reachable, it is just used for estblashing many 
  context with the peer (attack).*/
static const struct in6_addr EXP_LOC={{{0x20,01,06,0xa8,0x30,0x80,00,02,
					00,00,00,00,00,00,00,01}}};

/*Builds a loc option with the two given locators*/
static void build_attack_loc_option(struct in6_addr* loc1, 
				    struct in6_addr* loc2,
				    struct loc_list_opt *loclist)
{
	int opt_len;
	int nb_locs=2;
		
	opt_len=5+17*nb_locs;
	
	loclist->gen_nb=malloc(TOTAL_LENGTH(opt_len));
	if (!loclist->gen_nb) {
		fprintf(stderr,"%s:Not enough memory\n",__FUNCTION__);
		exit(EXIT_FAILURE);
	}
	loclist->num_locs=(uint8_t*)(loclist->gen_nb+1);
	loclist->verif_method=loclist->num_locs+1;
	loclist->padding=loclist->verif_method+nb_locs;
	loclist->locators=(struct in6_addr*)(loclist->padding+
					     PAD_LENGTH(opt_len));

	*loclist->gen_nb=htonl(0); /*the gen number is not important here*/
	*loclist->num_locs=nb_locs;

	memset(loclist->padding,0,PAD_LENGTH(opt_len));
	
	ipv6_addr_copy(&loclist->locators[0],loc1);
	ipv6_addr_copy(&loclist->locators[1],loc2);
	loclist->verif_method[0]=loclist->verif_method[1]=SHIM6_CGA;	
}

/*Builds a sign option*/
static void build_attack_sign_option(struct loc_list_opt *loclist,
				     struct signature *sgn,
				     struct cga_params *pds)
{
	sgn->sign=cga_sign(loclist,&sgn->slen,pds);
}

static void build_param_array(void)
{
	int i;

	if (glob_loc_sets.size != NB_EVAL_CGAS) {
		fprintf(stderr,"%s:Expected %d CGAs, but %d are configured\n",
			__FUNCTION__,NB_EVAL_CGAS,glob_loc_sets.size);
	}
	
	for (i=0;i<glob_loc_sets.size;i++) {
		shim6_loc_l* loc=&glob_loc_sets.lsetp[i];
		struct cga_params* cp=find_params_byaddr(&loc->addr,loc->ifidx);
		memcpy(&params[i].ulid,&glob_loc_sets.lsetp[i],
		       sizeof(shim6_loc_l));
		ipv6_addr_copy(&params[i].loc_2,&EXP_LOC);
		build_attack_loc_option(&params[i].ulid.addr,&params[i].loc_2,
					&params[i].loclist);
		params[i].pds=cp;
		build_attack_sign_option(&params[i].loclist,&params[i].sgn,
					 params[i].pds);
		params[i].pds=cp;
							       
	}
}

static void start_measure(struct tq_elem* timer)
{
	static int switcher=0;
	
	if (switcher==0) {
		if (eval_new_ctx(measure_sec, &ulid_peer)<0) {
			fprintf(stderr,"%s:eval_new_ctx failed\n",__FUNCTION__);
			exit(EXIT_FAILURE);
		}
		switcher=1;
	}
	else {
		if (eval_new_ctx(measure_sec, &ulid_peer2)<0) {
			fprintf(stderr,"%s:eval_new_ctx failed\n",__FUNCTION__);
			exit(EXIT_FAILURE);
		}
		switcher=0;		
	}
	
	if (!sequential) {
		/*Parallel measurements, start a new negotiation every 
		  PARALLEL_TIME ms*/
		if (eval_counter<NB_PARALLEL) 
			add_task_rel(&EVAL_RENEG,&eval_timer,
			start_measure);
	}
}


void end_measure(struct shim6_ctx* ctx)
{
	struct timespec stop;
	struct timespec total_time;
	static double time_array[NB_PARALLEL][4];
	static int count=0;

#define FULLNEG 0
#define INITCTX 1
#define RCVR1   2
#define RCVR2   3

	clock_gettime(CLOCK_REALTIME,&stop);
	tssub(stop,ctx->startneg,total_time);
	if (sequential) {
		printf("%f\n",tstodsec(total_time));	
		if (eval_counter<NB_SEQUENTIAL) {
			usleep(1000000);	
			start_measure(NULL);
		}
		else (exit(EXIT_SUCCESS));
	}
	else{
		/*In the parallel case, we do not print immediately the 
		  results, since printf takes time. Instead, we bufferize 
		  everything, and give all results in once when measurements 
		  are finished*/
		time_array[ctx->eval_counter][FULLNEG]=tstodsec(total_time);
		time_array[ctx->eval_counter][INITCTX]=
			tstodsec(ctx->initctx_time);
		time_array[ctx->eval_counter][RCVR1]=
			tstodsec(ctx->rcvr1_time);
		time_array[ctx->eval_counter][RCVR2]=
			tstodsec(ctx->rcvr2_time);

		count++;
		if (count==NB_PARALLEL) {
			int i;
			for (i=0;i<NB_PARALLEL;i++) {
				printf("%f %f %f %f\n",time_array[i][FULLNEG],
				       time_array[i][INITCTX],
				       time_array[i][RCVR1],
				       time_array[i][RCVR2]);
			}
			exit(EXIT_SUCCESS);		
		}
	}
	shim6_del_ctx(ctx);
}

/*===========================================*/

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
	mkdir(CONFIG_DIR "/shim6",00750); /*Create shim6 dir if necessary*/
	logfd=open(CONFIG_DIR "/shim6/shim6d.log",O_WRONLY|O_CREAT|O_APPEND,00640);
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
	struct addrinfo *res;
	struct addrinfo hints = {
		0,
		PF_INET6,
		SOCK_STREAM,
		0,
		0,
		NULL,
		NULL,
		NULL
	};

	if (argc!=6) {
		fprintf(stderr,"syntax : shim6eval <destination|any> "
			"<nosec|hba(-nocache)|cga(-nocache)> <client|server> "
			"n_src_addresses <seq | <second destination>>\n"
			"(in server mode, the first arg must be <any>,"
			" while in client mode\n"
			" it must be the ulid of the"
			" server)\n"
			" n is the number of local addresses,\n"
			" shim6eval starts the measurements only when" 
			" it knows all the addresses");
		exit(EXIT_FAILURE);
	}

	
	/*Parsing arg 1*/
	
	if (strcmp("any",argv[1])) {

		ans=getaddrinfo(argv[1],NULL,&hints,&res);
		if (ans) {
			fprintf(stderr,"%s:getaddrinfo failed\n",__FUNCTION__);
			fprintf(stderr,gai_strerror(ans));
			exit(EXIT_FAILURE);
		}
		ipv6_addr_copy(
			&ulid_peer,
			&((struct sockaddr_in6*)res->ai_addr)->sin6_addr);
		freeaddrinfo(res);
	}

	/*parsing arg 2*/

	if (!strcmp("nosec",argv[2])) measure_sec=0;
	else if (!strcmp("cga",argv[2])) measure_sec=SHIM6_CGA;
	else if (!strcmp("hba",argv[2])) measure_sec=SHIM6_HBA;
	else if (!strcmp("cga-nocache",argv[2])) {
		measure_sec=SHIM6_CGA;
		nooptcache=1;		
	}
	else if (!strcmp("hba-nocache",argv[2])) {
		measure_sec=SHIM6_HBA;
		nooptcache=1;
	}
	else {
		fprintf(stderr,"3rd arg must be nosec|cga(-nocache)|hba(-nocache)\n");
		exit(EXIT_FAILURE);
	}

	/*parsing arg 3*/
	if (!strcmp("server",argv[3])) server_mode=1;
	else if (!strcmp("client",argv[3])) server_mode=0;
	else {
		fprintf(stderr,"3rd arg must be client or server\n");
		exit(EXIT_FAILURE);
	}


	/*parsing arg 4*/
	naddrs=strtol(argv[4],NULL,10);
	if (naddrs==LONG_MAX || naddrs==LONG_MIN) {
		fprintf(stderr,"4th arg must be the number of "
			"local addresses\n");
		exit(EXIT_FAILURE);
	}
	/*Parsing arg 5*/
	if (!strcmp("seq",argv[5])) sequential=1;
	else {
		sequential=0;
		attack=1;
		ans=getaddrinfo(argv[5],NULL,&hints,&res);
		if (ans) {
			fprintf(stderr,"%s:getaddrinfo (arg 6)"
				" failed\n",
				__FUNCTION__);
			fprintf(stderr,gai_strerror(ans));
			exit(EXIT_FAILURE);
		}
		ipv6_addr_copy(
			&ulid_peer2,
			&((struct sockaddr_in6*)res->ai_addr)
			->sin6_addr);
		freeaddrinfo(res);		
	}

	/*If server mode, daemonize*/
	if (server_mode && daemonize()<0) {
		fprintf(stderr,"function daemonized() failed\n");
		exit(EXIT_FAILURE);
	}


	/* Open log */
	openlog("shim6eval",0,LOG_USER);
	
	
	/*Create a shim6eval.pid entry in ../run*/
	pidfile = fopen(LOCALSTATE_DIR "/run/shim6eval.pid", "w");
	
	if (pidfile == NULL) {
		syslog(LOG_ERR,
		       "Couldn't create pid file \""
		       LOCALSTATE_DIR "/run/shim6eval.pid\": "
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
	if (applog_open(applog_str2method("syslog"),"shim6eval")<0) {
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

	/*eval timer initialization*/
	init_timer(&eval_timer);

	/*If in parallel mode, build param list*/
	if (!sequential)
		build_param_array();

	while(1) {
		/* If client, starting first measure
		 * If the address number is not the expected one, 
		 * waiting for additional addresses to show up before 
		 * the starting of the measurements.
		 */
		if (!eval_started && !server_mode && nb_glob_locs()==naddrs) {
			/*Maybe all adresses are not yet present after
			  initialization, with this, we can start
			  measurements as soon as the addresses are all there*/
			start_measure(NULL);
			eval_started=1;
		}
		else if (!server_mode && !eval_started) {
			syslog(LOG_INFO,"naddr currently %d," 
			       "waiting to be %d\n",nb_glob_locs(),naddrs);
		}

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
				       "context -- discarded\n");
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
			case SHIM6_TYPE_R1:
				rcv_r1((shim6hdr_r1*) shim6hdr,&addr.sin6_addr,
					&pkt_info->ipi6_addr);
				break;
			case SHIM6_TYPE_R2:
				rcv_r2((shim6hdr_r2*) shim6hdr,&addr.sin6_addr,
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
