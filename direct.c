/*
 * Copyright (C) 2002-2006 Josh A. Beam
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* so useless... */

#include <stdio.h>
#include <sys/types.h>
#include "prtunnel.h"

extern char *proxyhost;
extern unsigned short proxyport;

extern int establish_connection(char *, unsigned short);

/* connect to hostname:port directly */
static int
direct_connect_to(struct prt_context *context,
                  char *hostname, unsigned short port,
                  char *username, char *password, int server_timeout)
{
	int fd;
	struct hostent *host;

	host = gethostbyname(hostname);
	if(!host)
		return -1;

	fd = establish_connection(host->h_addr, port);
	if(fd == -1)
		return -1;

	/* set remote server socket timeout if necessary */
	if(server_timeout) {
		struct timeval timeout_val;

		timeout_val.tv_sec = server_timeout;
		timeout_val.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout_val, sizeof(timeout_val));
	}

	return fd;
}

static void
direct_disconnect(struct prt_context *context)
{
	shutdown(context->localfd, SHUT_RDWR);
	shutdown(context->remotefd, SHUT_RDWR);
	close(context->localfd);
	close(context->remotefd);
}

static int
direct_local_read(struct prt_context *context, char *buf, int size)
{
	return recv(context->localfd, buf, size, 0);
}

static int
direct_remote_read(struct prt_context *context, char *buf, int size)
{
	return recv(context->remotefd, buf, size, 0);
}

static int
direct_local_send(struct prt_context *context, char *buf, int size)
{
	return send(context->localfd, buf, size, 0);
}

static int
direct_remote_send(struct prt_context *context, char *buf, int size)
{
	return send(context->remotefd, buf, size, 0);
}

void
direct_set_context(struct prt_context *context)
{
	context->connect = direct_connect_to;
	context->disconnect = direct_disconnect;
	context->local_read = direct_local_read;
	context->local_send = direct_local_send;
	context->remote_read = direct_remote_read;
	context->remote_send = direct_remote_send;

	context->data = NULL;
}
