/*
 *	LinShim6 implementation - information server
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
#include "info_server.h"
#include "pipe.h"
#include "xfrm.h"
#include <shim6/reapd.h>
#include <shim6/shim6d.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <pty.h>
#include <list.h>
#include <utils/debug.h>
#include <cryptoshim6/cga_params.h>
#include <cryptoshim6/cga.h>

#include "shim6_local.h"

/*Macro for activation/deactivation of debug messages*/

#undef PDEBUG
#ifdef SHIM6_DEBUG
# define PDEBUG(fmt,args...) syslog(LOG_INFO,fmt,##args)
#else
# define PDEBUG(fmt,args...)
#endif

static int listenfd=-1, connfd=-1;
static struct sockaddr_in cliaddr, servaddr;
pthread_t server_runner;

static pthread_cond_t ack=PTHREAD_COND_INITIALIZER;
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;

/*Path to shim6 proc files*/
char* proc_path="/proc/net/shim6/";

/*Variables for pseudo-terminal management*/
static int pty_master,pty_slave;
static int pipefd[2];
static pthread_t networkpty_thread;


/*Defs for console management (inspired from libappconsole)*/

/**
 * @outfd is the file descriptor to which the answer must be written.
 * @str is the full command, as it was typed by the user
 * @return : Always 0 except for the special 'quit' instruction, in which case
 *     it returns 1
 */
typedef int (*is_cmd_handler)(int outfd, char * str);

typedef struct {
	const char	*cmdstr;
	const char	*helpstr;
	int		cmdlen;
	is_cmd_handler  cmd_handler;
} is_cmd_t;

static int local_cmd_cnt;
static int main_thr_cmd_cnt;

LIST_HEAD(ct_list);
struct ct_node {
	struct list_head list;
	uint64_t ct;
};

/*==========================================================*/

/*Plugs the pty master side to the network socket*/
static void* networkpty(void* arg)
{	
	#define BUF_SIZE 30
	fd_set fdset;
	unsigned char buf[BUF_SIZE];
	int nbread;
	int ans;

	while(1) {
		FD_ZERO(&fdset);
		FD_SET(pty_master,&fdset);
		FD_SET(connfd,&fdset);
		FD_SET(pipefd[0],&fdset);
	
		ans=select(max(max(pty_master,connfd),pipefd[0])+1,
			   &fdset,NULL,NULL,NULL);
		
		if (ans<0) {
			PDEBUG("error in select : %m\n");
			exit(EXIT_FAILURE);
		}

		if (FD_ISSET(pipefd[0],&fdset)) {
			char c;
			read(pipefd[0],&c,1); /*freeing the pipe*/
			PDEBUG("closing of socket detected\n");
			pthread_exit(NULL);
		}
		
		if (FD_ISSET(pty_master,&fdset)) {
			nbread=read(pty_master,buf,BUF_SIZE);
			if (nbread>0)
				write(connfd,buf,nbread);
		}

		if (FD_ISSET(connfd,&fdset)) {
			nbread=read(connfd,buf,BUF_SIZE);
			if (nbread<0) {
				pthread_exit(NULL);
			}
			if (nbread>0)
				write(pty_master,buf,nbread);
		}
	}
}

/*@pre : str is the ascii representation of an hexadecimal number.
 *@post : the hex number is returned in binary form
 */
static __u64 strtoct (char* str)
{

	__u64 ret;

	if (sscanf(str,"%llx",&ret)<0) return -1;
	return ret;
}

/*Simple command handler for exiting the console*/
static int exit_console(int outfd, char* str)
{
	uint8_t oob = INFOSERV_CLOSE;
	/*Tell the client to terminate*/
	send(outfd,&oob,sizeof(oob),MSG_OOB);
	/*Tell the server to close this connexion*/
	return 1;
}

static void __print_valid_type(int fd, int valid_method)
{
	switch(valid_method) {
	case SHIM6_CGA:dprintf(fd,"(CGA)\n"); break;
	case SHIM6_HBA:dprintf(fd,"(HBA)\n"); break;
	default: dprintf(fd, "(Not HBA nor CGA)\n"); break;
	}
}

/*Print the state information for the given context*/

static void __one_state_info(int fd, struct shim6_ctx* ctx)
{
	struct reap_ctx* rctx;
	struct probe_address_node* probe_node;
	int i;
	int all_nonsecure, useall_locators, nb_loc_locs;
	struct in6_addr* locaddr_array=NULL;
	uint8_t* valid_method;
	
	rctx=&ctx->reap;
	
	dprintf(fd,"Information from user space daemon\n");
	dprintf(fd,"----------------------------------\n\n");
	
	dprintf(fd, "Global state : ");
	switch(ctx->state) {
	case SHIM6_IDLE: dprintf(fd, "idle\n"); break;
	case SHIM6_I1_SENT: dprintf(fd, "i1 sent\n"); break; 
	case SHIM6_I2_SENT: dprintf(fd, "i2 sent\n"); break;
	case SHIM6_ESTABLISHED: dprintf(fd, "established\n"); break;
	case SHIM6_I2BIS_SENT: dprintf(fd, "i2bis sent\n"); break;
	case SHIM6_E_FAILED: dprintf(fd, "e-failed\n"); break;
	case SHIM6_NO_SUPPORT: dprintf(fd, "no-support\n"); break;
	default: dprintf(fd,"unknown - This is a bug !\n"); break;
	}
	
	dprintf(fd,"local context tag : %llx\n",ctx->ct_local);
	dprintf(fd,"peer context tag : %llx\n",ctx->ct_peer);
	dprintf(fd,"Peer locator list : \n");
	for (i=0;i<ctx->ls_peer.size;i++) {
		dprintf(fd,"\t%s\n",addrtostr(&ctx->ls_peer.psetp[i].addr));	
	}

	/*Getting info about the local locator list*/
	nb_loc_locs=get_nb_loc_locs(ctx,FALSE,&all_nonsecure,&useall_locators,
				    NULL);
	if (nb_loc_locs<0) {
		dprintf(fd,"BUG : nb_loc_locs failed !\n");
		return;
	}
	locaddr_array=malloc(nb_loc_locs*sizeof(*locaddr_array)+
			     nb_loc_locs*sizeof(*valid_method));
	if (!locaddr_array) {
		APPLOG_NOMEM();
		exit(EXIT_FAILURE);
	}
	valid_method=(uint8_t*)(locaddr_array+nb_loc_locs);
	if (get_loc_locs_array(ctx,FALSE,locaddr_array,valid_method,
			       all_nonsecure, useall_locators,NULL)<0)
		dprintf(fd,"BUG : get_loc_locs_array failed !!\n");
	else {
		dprintf(fd,"Local locator list : \n");
		for (i=0;i<ctx->ls_localp->size;i++) {
			dprintf(fd,"\t%s ",
				addrtostr(&locaddr_array[i]));
			__print_valid_type(fd,valid_method[i]);
		}
	}
	free(locaddr_array);
	dprintf(fd,"Current local locator : ");
	dprintf(fd,"%s\n",addrtostr(&ctx->lp_local));
	dprintf(fd,"Current peer locator : ");
	dprintf(fd,"%s\n",addrtostr(&ctx->lp_peer));


	if (ctx->state==SHIM6_ESTABLISHED) {
		dprintf(fd,"REAP state : ");
		switch(rctx->state) {
		case REAP_OPERATIONAL: dprintf(fd,"operational\n"); break;
		case REAP_EXPLORING: dprintf(fd,"exploring\n"); break;
		case REAP_INBOUND_OK: dprintf(fd,"inbound_ok\n"); break;
		default:dprintf(fd,"unknown - This is a bug !\n"); break;
		}
		
		dprintf(fd,"Send timeout: %f seconds\n",
			tstodsec(rctx->send_timespec));
		dprintf(fd,"Keepalive timeout: %d seconds\n",rctx->tka);
		
		dprintf(fd,"nb probes sent : %d\n",rctx->nb_probes_sent);
		
		list_for_each_entry(probe_node,&rctx->sent_probes,list) {
			dprintf(fd,"* src : %s\n",
				addrtostr(&probe_node->content.src));
			dprintf(fd,"  dest : %s\n",
				addrtostr(&probe_node->content.dest));
			dprintf(fd,"  nonce : %x\n", 
				ntohl(probe_node->content.nonce));
			dprintf(fd,"  option : %x\n", 
				probe_node->content.option);		
		}
		dprintf(fd,"nb probes recvd : %d\n",rctx->nb_probes_recvd);
		list_for_each_entry(probe_node,&rctx->recvd_probes,list) {
			dprintf(fd,"* src : %s\n",
				addrtostr(&probe_node->content.src));
			dprintf(fd,"  dest : %s\n",
				addrtostr(&probe_node->content.dest));
			dprintf(fd,"  nonce : %x\n", 
				ntohl(probe_node->content.nonce));
			dprintf(fd,"  option : %x\n", 
				probe_node->content.option);
			
		}

		dprintf(fd,"Path array :\n");
		for (i=0;i<ctx->reap.path_array_size;i++) {
			struct shim6_path* p=&rctx->path_array[i];
			dprintf(fd,"\tsrc : %s\n",addrtostr(&p->local));
			dprintf(fd,"\tdest : %s\n",addrtostr(&p->remote));
		}
	}
}

/**
 *
 * Executes command 'cat <context tag>'
 * The state information of the Shim6 context having the given context tag
 * is written to @fd. <context tag> may also be '*', in which case all states
 * are dumped.
 * This function MUST be called from the main shim6d thread
 * (ask for execution through the pipe)
 */
static int __state_info(int fd, char* ct_str)
{
	int i;
	struct shim6_ctx* ctx;
	__u64 ct;

	if (strlen(ct_str) < 5) return 0;
	ct_str+=4; /*Pointing to the argument*/
	
	if (*ct_str=='*') {
		for (i=0;i<SHIM6_HASH_SIZE;i++) {
			list_for_each_entry(ctx,&ct_hashtable[i],collide_ct) {
				ASSERT(ctx!=NULL);
				dprintf(fd,"++++++++++++++++++++++++++++++\n");
				__one_state_info(fd,ctx);
			}
		}
		return 0;
	}

	ct=strtoct(ct_str);
	if (ct==-1) {
		dprintf(fd,"cat: invalid context tag\n");
		return 0;
	}

	ctx=lookup_ct(ct);

	if (!ctx) {
		dprintf(fd,"cat: %llx: no such state\n",ct);
		return 0;
	}

	
	__one_state_info(fd,ctx);

	return 0;
}

/* This function MUST be called from the main shim6d thread
 * (ask for execution through the pipe)
 */
static int __state_del(int fd, char* ct_str)
{
	uint64_t ct;
	struct shim6_ctx *ctx,*tmp;
	int i;

	if (strlen(ct_str)<4) return 0;
	ct_str+=3; /*Removing the 'rm'*/
	
	if (*ct_str=='*') {
		for (i=0;i<SHIM6_HASH_SIZE;i++) {
			list_for_each_entry_safe(ctx,tmp,&ct_hashtable[i],
						 collide_ct) {
				ASSERT(ctx!=NULL);
				shim6_del_ctx(ctx);
			}
		}
		return 0;
	}

	ct=strtoct(ct_str);
	if (ct==-1) {
		dprintf(fd,"del: invalid context tag\n");
		return 0;
	}
	
	ctx=lookup_ct(ct);
	
	if (!ctx) {
		dprintf(fd,"del: %llx: no such state\n",ct);
		return 0;
	}
	shim6_del_ctx(ctx);

	return 0;
}

/* This function MUST be called from the main shim6d thread
 * (ask for execution through the pipe)
 */
static int __list_states(int fd, char* str)
{
	int i;
	struct shim6_ctx* ctx;
	
	for (i=0;i<SHIM6_HASH_SIZE;i++) {
		list_for_each_entry(ctx,&ct_hashtable[i],collide_ct) {
			ASSERT(ctx!=NULL);
			dprintf(fd,"%llx\n",ctx->ct_local);
			PDEBUG("%s: ctx found at entry %d\n",__FUNCTION__,i);
		}
	}
	return 0;
}

static int __number_of_contexts(int fd, char* str)
{
	int i;
	struct shim6_ctx* ctx;
	int nb=0;
	
	for (i=0;i<SHIM6_HASH_SIZE;i++)
		list_for_each_entry(ctx,&ct_hashtable[i],collide_ct)
			nb++;
	dprintf(fd,"%d\n",nb);
	return 0;
}

static void free_ct_list(void)
{
	struct ct_node *it,*temp;
	
	list_for_each_entry_safe(it, temp, &ct_list,list) {
		list_del(&it->list);
		free(it);
	}
}


static void __update_ct_list(void)
{	
	int i;
	struct shim6_ctx* ctx;
	struct ct_node* new_node;
	
	free_ct_list();
	
	/*Build a new one*/
	for (i=0;i<SHIM6_HASH_SIZE;i++) {
		list_for_each_entry(ctx,&ct_hashtable[i],collide_ct) {
			ASSERT(ctx!=NULL);
			new_node=malloc(sizeof(struct ct_node));
			if (!new_node) {
				PDEBUG("%s : not enough memory\n",__FUNCTION__);
				return;
			}
			new_node->ct=ctx->ct_local;
			list_add_tail(&new_node->list,&ct_list);
		}
	}
}

static void update_ct_list(void)
{
	pthread_mutex_lock(&mutex);
	pipe_push_event(PIPE_EVENT_INFO_SRV,"update_ct_list");
	pthread_cond_wait(&ack,&mutex);
	pthread_mutex_unlock(&mutex);				
}

static int __dump_cga_params(int fd, char* str)
{
	dump_params(fd);
	return 0;
}

static void __address_type(int fd, struct in6_addr* addr, int ifidx)
{
	int vm=get_valid_method(addr,ifidx,NULL);
	switch (vm) {
	case SHIM6_CGA:
		dprintf(fd,"CGA\n");
		break;
	case SHIM6_HBA:
		dprintf(fd,"HBA\n");
		break;
	case 0:
		dprintf(fd,"Non-secured address\n");
		break;
	default:
		dprintf(fd,"Unknown\n");
	}
}

static int  __show_local_addresses(int fd, char* str)
{
	int list_cnt;
	struct locset* ls;
	list_for_each_entry_all(ls,&glob_loc_sets.list,list,list_cnt) {
		int i;
		for (i=0;i<ls->size;i++) {
			dprintf(fd,"%s : ",addrtostr(&ls->lsetp[i].addr));
		        __address_type(fd,&ls->lsetp[i].addr,
				       ls->lsetp[i].ifidx);
		}
	}
	return 0;
}

static int __set_tsend(int fd, char* str)
{
	long new;
	char *end;
	if (strlen(str)<11) return 0;
	str+=10; /*Pointing to the argument*/
	
	new=strtol(str,&end,10);
	
	/*Checks for correctness*/
	if (end==str) {
		dprintf(fd,"Impossible to parse argument: %s\n",str);
		return 0;
	}
	if (new<=0 || new>=0x0FFFF) {
		dprintf(fd, "Out of range\n");
		return 0;
	}
	
	if (new<10) 
		dprintf(fd,"warning:it is recommended not to set "
			"tsend below 10 seconds\n");
	
	/*Setting tsend*/
	set_tsend(new);
	
	dprintf(fd, "Send timeout set to %d seconds\n",(uint16_t)new);

	return 0;
}

#ifdef LOG_EXPL_TIME
static int reset_timelog(int fd, char* str)
{
	int expl_fd;
	expl_fd=open("/etc/shim6/expl.log", O_TRUNC);
	close(expl_fd);
	return 0;
}

static int get_timelog(int streamfd, char* str)
{
	int fd=-1;
	int ans;
	char buffer[BUFFER_SIZE];
	
	fd=open("/etc/shim6/expl.log",O_RDONLY);
	if (fd<0) {
		syslog(LOG_ERR,"get_timelog, open : %m\n");
		return 0;
	}

	while ((ans=read(fd,buffer,BUFFER_SIZE))==BUFFER_SIZE) {
		write(streamfd,buffer,BUFFER_SIZE);
	}
	if (ans<0) {
		syslog(LOG_ERR,"get_timelog, read : %m\n");
		goto failure;
	}
	ans=write(streamfd,buffer,ans);
	if (ans<0) {
		syslog(LOG_ERR,"get_timelog, write : %m\n");
		goto failure;
	}
	
 failure:
	if (fd!=-1) close(fd);
	return 0;
}
#endif

/*We must declare it here, and implement it after the definition
 * of local_cmds, because one uses the other*/
static int dohelp(int outfd, char* str);

static is_cmd_t local_cmds[] = {
	{ "quit", "Quit the Shim6 console", 1, exit_console },
	{ "exit", "Quit the Shim6 console", 1, exit_console },
	{ "?", "Shows help", 1, dohelp},
	{ "help", "Shows help", 1, dohelp},
	{ "dkc", "Dump kernel contexts",3,
	  dump_all_kern_states},
	{ "dkp", "Dump kernel policies",3,
	  dump_all_kern_policies},
#ifdef LOG_EXPL_TIME
	{ "reset timelog", "Reset the log file for exploration time analysis", 
	  7, reset_timelog},
	{ "get timelog", "Print the log file for exploration time analysis",
	  5, get_timelog},
#endif /*LOG_EXPL_TIME*/
};

static is_cmd_t main_thr_cmds[] = {
	{ "ls", "List current available context, by context tags", 1,
	  __list_states},
	{ "cat", "Displays details about the context with the given local " 
	  "context tag", 3, __state_info},
	{ "rm", "Manually deletes the context with the given local "
	  "context tag\n\tfrom kernel and daemon", 2, __state_del},
	{ "dcp", "Dumps all CGA parameters stored in the daemon",
	  3, __dump_cga_params},
	{ "sla", "Show local addresses", 2, __show_local_addresses},
	{ "nbc", "Number of contexts", 3, __number_of_contexts},
	{ "set tsend","Set Tsend timer",9, __set_tsend },
};


static int dohelp(int outfd, char* str)
{
	int i;

	for (i = 0; i < local_cmd_cnt; i++) {
		dprintf(outfd, "%s\t%s\n", local_cmds[i].cmdstr, 
			local_cmds[i].helpstr);
	}
	for (i = 0; i < main_thr_cmd_cnt; i++) {
		dprintf(outfd, "%s\t%s\n", main_thr_cmds[i].cmdstr, 
			main_thr_cmds[i].helpstr);
	}
	return 0;
}

static char *
possible_cmds(const char *text, int state)
{
	static int len, idx;
	
	static int ct_completion;
	static struct ct_node* cur_node;
	
	if (state == 0) {
		idx = ct_completion = 0;
		len = strlen(text);

		
		if (strncasecmp("cat ",rl_line_buffer, 4)==0 ||
		    strncasecmp("rm ",rl_line_buffer,3)==0) {
			ct_completion=1;
			update_ct_list();
			cur_node=list_first_entry(&ct_list,struct ct_node,list);
			if (!cur_node) return NULL;
		}
	}
	
	if (!ct_completion) {
		for (; idx < local_cmd_cnt; idx++) {
			if (strncmp(local_cmds[idx].cmdstr, text, len) == 0) {
				return (strdup(local_cmds[idx++].cmdstr));
			}
		}
		
		for (; idx < local_cmd_cnt+main_thr_cmd_cnt; idx++) {
			if (strncmp(main_thr_cmds[idx-local_cmd_cnt].cmdstr, 
				    text, 
				    len) == 0) {
				char* newstr=strdup(main_thr_cmds
						    [idx-local_cmd_cnt].cmdstr);
				idx++;
				return newstr;
			}
		}
	}

	else { 

		for (;cur_node->list.next && &cur_node->list != &ct_list;
		     cur_node = list_entry(cur_node->list.next, 
					   struct ct_node, list)) {
			char* str=malloc(20);
			if (!str) {
				PDEBUG("%s : not enough memory\n",__FUNCTION__);
				break;
			}
			sprintf(str,"0x%llx",cur_node->ct);
			if (strncasecmp(str,text,len)==0) {
				cur_node = list_entry(cur_node->list.next, 
						      struct ct_node, list);
				return str;
			}
			if (strncasecmp(str+2,text,len)==0) {
				char* str2=strdup(str+2);
				cur_node = list_entry(cur_node->list.next, 
						      struct ct_node, list);
				free(str);
				return str2;
			}
			free(str);
		}
		free_ct_list();
	}

			
	return (NULL);
}

static void clear_pipe(void)
{
	char c;
	int flags;
	
	/*Setting non blocking I/O, because the character may or may not 
	  be in the pipe :
	  - it is in if the thread exited for another reason than detecting
	  character arrival in the pipe. (reading error)
	  - It is not there anymore if the pipe read the character already.*/
	if (-1 == (flags = fcntl(pipefd[0], F_GETFL, 0)))
		flags = 0;
	fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
	read(pipefd[0], &c,1);
	fcntl(pipefd[0], F_SETFL, flags); /*Restoring blocking I/O*/
}

/*TODO : Handle the SIGPIPE, which is received in case of broken 
 * stream : The idea is to do nothing when receiving sigpipe, but only
 * the will interrupt the dprintf with EPIPE. A check followed by a close of
 * the socket is the proper thing to do. It not necessary to check each 
 * dprintf, since each one will produce a sigpipe (ignored) than will return 
 * with errno set to EINTR and the program will proceed. We must only ensure 
 * that eventually we will stop trying and close the socket.*/
static void* runner(void* arg)
{
	socklen_t cliaddr_len=sizeof(cliaddr);
	FILE* stream;
	int c=0;
	int i;
	char* command;

	while(1) {

		connfd=accept(listenfd,(struct sockaddr*)&cliaddr,
			      &cliaddr_len);
		if (connfd<0) continue;
		PDEBUG("info server : new connexion\n");
		if (pthread_create(&networkpty_thread,NULL,networkpty,NULL)<0) {
			PDEBUG("pthread_create failed : %m\n");
			close(connfd);
			continue;
		}
		stream=fdopen(pty_slave,"r+");
		if (!stream) continue;
		rl_instream=rl_outstream=stream;
		rl_completion_entry_function = possible_cmds;
		using_history();
		
		while (1) {
			HIST_ENTRY* cur_hist;
			/*Reading the command*/
			command=readline("LinShim6-" PACKAGE_VERSION ">");
			/*got a broken pipe signal?*/
			if (bpipe) {
				bpipe=0;
				break;
			}
			if (!command) continue;

			/*Can the command be executed in this thread ?*/
			for (i = 0; i < local_cmd_cnt; i++) {
				if (strncasecmp(local_cmds[i].cmdstr, command, 
						local_cmds[i].cmdlen) == 0) {
					if (local_cmds[i].cmd_handler(connfd,
								      command)
					    ==1)
						goto close_conn;
					else goto next;
				}
			}
			
			/*The other commands must be executed by the
			  main thread*/
			pthread_mutex_lock(&mutex);
			pipe_push_event(PIPE_EVENT_INFO_SRV,command);
			pthread_cond_wait(&ack,&mutex);
			pthread_mutex_unlock(&mutex);			
		next:			
			cur_hist=history_get(where_history());
			if (!cur_hist || strcmp(cur_hist->line,command))  {
				add_history(command);
			}
			free(command);
		}
	close_conn:
		write(pipefd[1],&c,1);
		PDEBUG("%s : Joining networkpty_thread...",__FILE__);
		pthread_join(networkpty_thread,NULL);
		PDEBUG("    ...done");
		clear_pipe(); /*We need to clear the pipe, because if the 
				character has not been eaten by the thread,
				the next connexion will be killed immediately*/
		close(connfd);
	}
	
	return NULL;
}

/*This initializes the server and returns 0 in case of success, 
 * a non zero value in case of failure.*/
int init_info_server()
{
	int ret;
	
	listenfd=socket(AF_INET,SOCK_STREAM,0);
	if (listenfd<0) return listenfd;
	
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	servaddr.sin_port=htons(INFOSERV_PORT);

	ret=bind(listenfd, (struct sockaddr*) &servaddr,sizeof(servaddr));
	if (ret<0) goto failure;

	ret=listen(listenfd,1); /*This version only allows one client 
				  at a time*/
	if (ret<0) goto failure;
	if (pipe(pipefd)<0) goto failure;
	openpty(&pty_master,&pty_slave,NULL,NULL,NULL);
	
	/*Start a new thread to accept connections*/
	ret=pthread_create(&server_runner,NULL,runner,NULL);
	if (ret) goto failure;

	local_cmd_cnt=sizeof (local_cmds) / sizeof (*local_cmds);
	main_thr_cmd_cnt=sizeof (main_thr_cmds) / sizeof (*main_thr_cmds);

	return 0; /*success*/
failure:
	if (listenfd>0) close(listenfd);
	return ret;
}

void exit_info_server()
{
	if (listenfd!=-1) close(listenfd);
	if (connfd!=-1) close(connfd);
	pthread_kill(server_runner,SIGTERM);
	pthread_join(server_runner,NULL);
}

void info_srv_handler(void* data)
{
	char* str=(char*) data;
	int i;
	
	/*Private handlers*/
	if (!strcmp(str,"update_ct_list")) {
		__update_ct_list();
		goto end;
	}

	/*Commands for*/

	for (i = 0; i < main_thr_cmd_cnt; i++) {
		if (strncasecmp(main_thr_cmds[i].cmdstr, str, 
				main_thr_cmds[i].cmdlen) == 0) {
			main_thr_cmds[i].cmd_handler(connfd,str);
			goto end;
		}
	}

end:
/*The info_server thread can now show the prompt again*/
	pthread_mutex_lock(&mutex);
	pthread_cond_signal(&ack);
	pthread_mutex_unlock(&mutex);
}
