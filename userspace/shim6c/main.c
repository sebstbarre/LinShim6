/*
 *	LinShim6 implementation - Shim6 console
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : March 2008
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <config.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <termios.h>
#include <unistd.h>
#include <shim6/shim6d.h>
#include <utils/util.h>

static int sock;
#define BUF_SIZE 80


/**
 * Opens a connection to the information server of a Shim6 host @host,
 * at port @serv. This function is provided by the book "IPv6, théorie et
 * pratique", Gisèle Cizault, O'Reilly.
 * 
 */
static int open_conn(char *host, char *serv)
{
	int ecode;
	struct addrinfo *res;
	struct addrinfo hints = {
		0,
		PF_UNSPEC,
		SOCK_STREAM,
		0,
		0,
		NULL,
		NULL,
		NULL
	};
	
	ecode = getaddrinfo(host, serv, &hints, &res);
	
	if (ecode) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ecode));
		exit(1);
	}
	if ((sock = socket(res->ai_family, res->ai_socktype, 
			   res->ai_protocol)) < 0) {
		freeaddrinfo(res);
		perror("socket");
		return -1;
	}
	
	if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
		close(sock);
		freeaddrinfo(res);
		perror("connect");
		return -1;
   }
	freeaddrinfo(res);
	return sock;
}


int main(int argc, char* argv[])
{
	fd_set fdset;
	fd_set ctlset;
	int ans;
	char buf[BUF_SIZE];
	struct termios termstate;
	struct termios termorig;
	uint8_t oob;

	if (argc!=2) {
		fprintf(stderr,"Syntax : shim6c <destination>\n");
		exit(EXIT_FAILURE);
	}
	if (open_conn(argv[1],xstr(INFOSERV_PORT))<0)
		fprintf(stderr,"Error opening connexion to Shim6 host\n");

	tcgetattr(STDIN_FILENO,&termstate);
	termorig=termstate;
	termstate.c_lflag &= ~(ECHO|ICANON);
	tcsetattr(STDIN_FILENO,TCSAFLUSH,&termstate);
	
	while(1) {
		int justreadoob=0;
		FD_ZERO(&fdset);
		FD_ZERO(&ctlset);
		FD_SET(STDIN_FILENO,&fdset);
		FD_SET(sock,&fdset);
		if (!justreadoob) FD_SET(sock,&ctlset);
		ans=select(max(STDIN_FILENO,sock)+1,&fdset,NULL,&ctlset,NULL);
		if (ans<0) {
			if (errno==EINTR) exit(EXIT_SUCCESS);
			fprintf(stderr, "select: %m\n");
			tcsetattr(STDIN_FILENO,TCSAFLUSH,&termorig);
			exit(EXIT_FAILURE);
		}
		if (FD_ISSET(sock,&ctlset)) {
			recv(sock,&oob,sizeof(oob),MSG_OOB);
			switch(oob) {
			case INFOSERV_CLOSE:
				printf("Connection closed by foreign host\n");
				tcsetattr(STDIN_FILENO,TCSAFLUSH,&termorig);
				exit(EXIT_SUCCESS);
				break;
			}
			justreadoob=1;
		}
		
		if (FD_ISSET(sock,&fdset)) {			
			ans=recv(sock,buf,BUF_SIZE,0);
			if (ans>0) { 
				if (write(STDOUT_FILENO,buf,ans)!=ans) {
					perror("write to stdout");
					tcsetattr(STDIN_FILENO,TCSAFLUSH,
						  &termorig);
					exit(EXIT_FAILURE);
				}
			}
			else {
				perror("read from network");
				tcsetattr(STDIN_FILENO,TCSAFLUSH,&termorig);
				exit(EXIT_FAILURE);
			}
			justreadoob=0;
		}
		if (FD_ISSET(STDIN_FILENO,&fdset)) {
			ans=read(STDIN_FILENO,buf,BUF_SIZE);
			if (ans>0 && write(sock,buf,ans)!=ans) {
				perror("write to network");
				tcsetattr(STDIN_FILENO,TCSAFLUSH,&termorig);
				exit(EXIT_FAILURE);
			}
		}
	}       
	tcsetattr(STDIN_FILENO,TCSAFLUSH,&termorig);
	return EXIT_SUCCESS;
}
