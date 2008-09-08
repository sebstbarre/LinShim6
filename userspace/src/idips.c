/*
 *	Linux shim6 implementation - Interaction with the IDIPS client daemon
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

#ifdef IDIPS

#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <dlfcn.h>
#include <idips/client.h>
#include <linux/shim6.h>

#include <utils/debug.h>
#include <shim6/shim6d.h>
#include "pipe.h"
#include "xfrm.h"

CREATE_LIST create_list;
ADD_PREFIX_TO_LIST add_prefix_to_list;
PREPARE_REQUEST prepare_request;
SEND_REQUEST send_request;
CLIENT_INIT client_init;
CLIENT_CLOSE client_close;

static pthread_cond_t ack=PTHREAD_COND_INITIALIZER;
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;

struct idips_data {
	__u64* ct;
	const struct daemon_message* dm;
};

/*Initialize the IDIPS module*/
int idips_init(void)
{
	void * handler = dlopen("idips/client_lib.so", RTLD_LAZY);
	
	if(!handler){
		syslog(LOG_ERR, "Could not find shared library "
		       "idips/client_lib.so\n");
		return -1;
	}
	
	/* retrieve functions */

	create_list = dlsym(handler, "create_list");
	add_prefix_to_list = dlsym(handler, "add_prefix_to_list");
	prepare_request = dlsym(handler, "prepare_request");
	send_request = dlsym(handler, "send_request");
	client_init = dlsym(handler, "client_init");

	if (!create_list || !add_prefix_to_list || !prepare_request || 
	    !send_request || !client_init) {
		syslog(LOG_ERR,"One handler has not been found\n");
		return -1;
	}

	if (!client_init()) return -1;
	return 0;
}


/*This function may be called only once for a given value of @context, because
 * the corresponding memory is freed here. @context is a pointer allocated 
 * inside idips_send_request()*/
static int idips_callback(const struct daemon_message *dm, int n, void *context)
{
	__u64* ct=(__u64*) context;
	struct idips_data data={ct,dm};
	
	pthread_mutex_lock(&mutex);				
	pipe_push_event(PIPE_EVENT_IDIPS, &data);
	pthread_cond_wait(&ack,&mutex);
	pthread_mutex_unlock(&mutex);			

	free(ct);
	return 0;
}

void idips_pipe_handler(void* data)
{
	struct shim6_ctx* ctx;
	struct reap_ctx* rctx;
	struct idips_data* idata=(struct idips_data*) data;
	int i,j;
	struct daemon_response_message* drm=
		(struct daemon_response_message*) idata->dm;
	struct path* temp_array;
	
		
	
	/*Verify that the message is an idips response*/
	if (idata->dm->type!=DAEMON_CLIENT_TYPE_RESPONSE) {
		syslog(LOG_ERR,"Bad answer received from IDIPS\n");
		return;
	}		

	ctx=lookup_ct(*idata->ct);
	if (!ctx) {
		PDEBUG("%s:an idips answer arrived for a removed context\n",
		       __FUNCTION__);
		return;
	}
	rctx=&ctx->reap;

	/*Check the array size (IDIPS may return less couples than what the
	  context actually have, since some may be known not to work. But it
	  is incorrect for IDIPS to return _more_ couples)*/
	if (rctx->path_array_size < drm->size_cpls) {
		syslog(LOG_ERR,"IDIPS returned %d couples, while this"
		       " context have %d couples\n",drm->size_cpls,
			rctx->path_array_size);
		return;
	}

	/*Checking which paths have any flags enabled (the flags must be kept
	 * after the update)
	 * (probably this part could be optimized)*/
	temp_array=malloc(drm->size_cpls*sizeof(struct path));
	for (i=0;i<drm->size_cpls;i++) {
		temp_array[i].flags=0;
		ipv6_addr_copy(&temp_array[i].src,
			       (struct in6_addr*)(drm+1)+2*i);
		ipv6_addr_copy(&temp_array[i].dest,
			       (struct in6_addr*)(drm+1)+2*i+1);		
	}
	for (i=0;i<rctx->path_array_size;i++) {
		if (rctx->path_array[i].flags) {
			for (j=0;j<drm->size_cpls;j++) {
				if (ipv6_addr_equal(&rctx->path_array[i].src,
						    &temp_array[j].src) &&
				    ipv6_addr_equal(&rctx->path_array[i].dest,
						    &temp_array[j].dest)) {
					temp_array[j].flags=
						rctx->path_array[i].flags;
					break;
				}
			}
		}
	}
	/*Flags have been copied, we can now update the reap context*/
	rctx->path_array=realloc(rctx->path_array,
				 drm->size_cpls*sizeof(struct path));
	memcpy(rctx->path_array,temp_array,drm->size_cpls*sizeof(struct path));
	rctx->cur_path_index=0;
	free(temp_array);

	/*If we are not exploring, maybe it is worth replacing the current
	  locator pair with the best one in the sense of IDIPS*/
	if (rctx->state==REAP_OPERATIONAL &&
	    (!ipv6_addr_equal(&ctx->lp_local,&rctx->path_array->src) ||
	     !ipv6_addr_equal(&ctx->lp_peer,&rctx->path_array->dest))) {
		xfrm_update_shim6_ctx(ctx,&rctx->path_array->dest,
				      &rctx->path_array->src);
	}
	
	/*The idips thread can now continue*/
	pthread_mutex_lock(&mutex);
	pthread_cond_signal(&ack);
	pthread_mutex_unlock(&mutex);	
	
}

/*Asynchronously makes an idips request. The answer will be received by
  callback, and managed through the pipe, in order to modify the REAP path 
  array from the main thread.
  
  We give a pointer to the IDIPS request function, so that we can find the
  right context later. Because the Shim6 context may have disappeared between 
  the IDIPS request and response, we cannot use the pointer to the context.
  Instead, we allocate memory for the context tag, so that the callback function
  can make a lookup for this particular context tag.
  The callback function is thus supposed to free the memory allocated here for
  the context tag.
*/
int idips_send_request(struct shim6_ctx *ctx)
{
	struct idips_list *srcs=NULL,*dsts=NULL;
	struct daemon_request_message *request;
	int i;
	size_t len=0;
	uint64_t* ctp=malloc(sizeof(uint64_t));
	struct in6_addr* locaddr_array=NULL;
	int nb_loc_locs,all_nonsecure,useall_locators;
  
	if (!ctp) goto failure;
	else *ctp=ctx->ct_local;

	/*Getting the array of local locators*/
	nb_loc_locs=get_nb_loc_locs(ctx,FALSE,&all_nonsecure,&useall_locators,
				    NULL);	
	if (nb_loc_locs<0) return -1;
	locaddr_array=malloc(nb_loc_locs*sizeof(*locaddr_array));
	if (!locaddr_array) {
		APPLOG_NOMEM();
		exit(EXIT_FAILURE);
	}

		
	/*Building local loc array*/
	if (get_loc_locs_array(ctx,FALSE,locaddr_array,NULL,all_nonsecure,
			       useall_locators,NULL)<0) goto failure;


	/* Prepare the lists of parameters */
	for (i=0;i<nb_loc_locs;i++)
		add_prefix_to_list(srcs,AF_INET6,128,&locaddr_array[i]);
	
	/* create and populate the list of destination IPs */
	for (i=0;i<ctx->ls_peer.size;i++)
		add_prefix_to_list(dsts,AF_INET6,128,
				   &ctx->ls_peer.psetp[i].addr);

	
	request = prepare_request(IDIPS_TOS_DEFAULT, srcs, dsts, &len);
	if(!send_request(request, idips_callback, (void *)ctp, &len)){
		syslog(LOG_ERR, "_send_request error\n");
		goto failure;
	}

	free(srcs);free(dsts);free(locaddr_array);
	return 0;
failure:
	if (ctp) free(ctp);
	if (srcs) free(srcs);
	if (dsts) free(dsts);
	if (locaddr_array) free(locaddr_array);
	return -1;
}

#endif
