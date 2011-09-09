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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "prtunnel.h"

extern int flags;

extern char *proxyhost;
extern unsigned short proxyport;

extern int establish_connection(char *, unsigned short);
#ifdef IPV6
extern int establish_connection6(char *, unsigned short);
#endif /* IPV6 */

extern int read_byte(int);

/* base64 characters */
static char b64chars[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

#define BASE64LEN 512
/* return base64 encoded string */
static char *
base64(char *s)
{
	int i, j;
	unsigned int bits = 0;
	unsigned char tmp[4];
	static char out[BASE64LEN];

	j = 0;
	for(i = 0; i < strlen(s) && (j-4) < (BASE64LEN - 1); i++) {
		bits <<= 8;
		bits |= s[i] & 0xff;

		if(!((i+1) % 3)) {
			tmp[0] = (bits >> 18) & 0x3f;
			tmp[1] = (bits >> 12) & 0x3f;
			tmp[2] = (bits >> 6) & 0x3f;
			tmp[3] = bits & 0x3f;
			bits = 0;

			out[j++] = b64chars[(tmp[0])];
			out[j++] = b64chars[(tmp[1])];
			out[j++] = b64chars[(tmp[2])];
			out[j++] = b64chars[(tmp[3])];
		}
	}
	switch(i % 3) {
		default:
			break;
		case 2:
			tmp[0] = (bits >> 10) & 0x3f;
			tmp[1] = (bits >> 4) & 0x3f;
			tmp[2] = (bits << 2) & 0x3f;

			out[j++] = b64chars[(tmp[0])];
			out[j++] = b64chars[(tmp[1])];
			out[j++] = b64chars[(tmp[2])];
			out[j++] = '=';
			break;
		case 1:
			tmp[0] = (bits >> 2) & 0x3f;
			tmp[1] = (bits << 4) & 0x3f;

			out[j++] = b64chars[(tmp[0])];
			out[j++] = b64chars[(tmp[1])];
			out[j++] = '=';
			out[j++] = '=';
			break;
	}

	out[j] = '\0';
	return out;
}
#undef BASE64LEN

static int
http_negotiate(int fd, char *hostname, unsigned short port,
               char *username, char *password, int use_http_1_0)
{
	int i;
	char buf[1024];
	int len;

	if(username && password) {
		char *tmp;

		snprintf(buf, 1024, "%s:%s", username, password);
		tmp = base64(buf);
		if(use_http_1_0)
			snprintf(buf, 1024, "CONNECT %s:%u HTTP/1.0\r\nProxy-Authorization: Basic %s\r\n\r\n", hostname, port, tmp); /* untested; sorry, I don't use auth. */
		else
			snprintf(buf, 1024, "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\nProxy-Authorization: Basic %s\r\n\r\n", hostname, port, hostname, port, tmp); /* untested; sorry, I don't use auth. */
	} else {
		if(use_http_1_0)
			snprintf(buf, 1024, "CONNECT %s:%u HTTP/1.0\r\n\r\n", hostname, port);
		else
			snprintf(buf, 1024, "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n\r\n", hostname, port, hostname, port);
	}
	send(fd, buf, strlen(buf), 0);

	len = recv(fd, buf, 12, 0);
	if(len <= 0) {
		fprintf(stderr, "Error: Couldn't read from proxy after sending CONNECT command\n");
		close(fd);
		return -1;
	}
	buf[len] = '\0';
	if(  (strcmp(buf, "HTTP/1.1 200") != 0) &&
	     (strcmp(buf, "HTTP/1.0 200") != 0) ) {
		fprintf(stderr, "HTTP Error: %s\n", buf);
		shutdown(fd, SHUT_RDWR);
		close(fd);
		return -1;
	}

	/*
	 * the proxy might send some headers we don't need,
	 * so we just keep reading bytes until we get \r\n\r\n
	 */
	for(i = 0; i < 4; i++) {
		buf[i] = read_byte(fd);
		if(buf[i] == -1) {
			close(fd);
			fprintf(stderr, "Error: Expected HTTP byte but couldn't read one\n");
			return -1;
		}
	}
	while(strncmp(buf, "\r\n\r\n", 4) != 0) {
		for(i = 0; i < 3; i++)
			buf[i] = buf[i+1];
		buf[3] = read_byte(fd);
		if(buf[3] == -1) {
			close(fd);
			fprintf(stderr, "Error: Expected HTTP byte but couldn't read one\n");
			return -1;
		}
	}

	return 0;
}

/* connect to hostname:port via an http proxy; returns file descriptor */
static int
http_connect_to(struct prt_context *context,
                char *hostname, unsigned short port,
                char *username, char *password, int server_timeout)
{
	int fd;
	struct hostent *host;
	int use_http_1_0;

	if(!proxyhost) {
		fprintf(stderr, "Error: No HTTP proxy host set\n");
		return -1;
	}

#ifdef IPV6
	if(flags & PRT_IPV6)
		host = gethostbyname2(proxyhost, AF_INET6);
	else
		host = gethostbyname2(proxyhost, AF_INET);
#else
	host = gethostbyname(proxyhost);
#endif /* IPV6 */
	if(!host) {
		fprintf(stderr, "Error: Unable to resolve hostname %s\n", proxyhost);
		return -1;
	}

#ifdef IPV6
	if(flags & PRT_IPV6)
		fd = establish_connection6(host->h_addr, proxyport);
	else
#endif /* IPV6 */
		fd = establish_connection(host->h_addr, proxyport);
	if(fd == -1) {
		fprintf(stderr, "Error: Unable to connect to HTTP proxy %s:%u\n", proxyhost, proxyport);
		return -1;
	}

	/* set remote server socket timeout if necessary */
	if(server_timeout) {
		struct timeval timeout_val;

		timeout_val.tv_sec = server_timeout;
		timeout_val.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout_val, sizeof(timeout_val));
	}

	fprintf(stderr, "Connected to HTTP proxy %s:%u\n", proxyhost, proxyport);

	if(flags & PRT_HTTP_1_0)
		use_http_1_0 = 1;
	else
		use_http_1_0 = 0;
	if(http_negotiate(fd, hostname, port, username, password, use_http_1_0) == -1)
		return -1;

	return fd;
}

static void
http_disconnect(struct prt_context *context)
{
	shutdown(context->localfd, SHUT_RDWR);
	shutdown(context->remotefd, SHUT_RDWR);
	close(context->localfd);
	close(context->remotefd);
}

static int
http_local_read(struct prt_context *context, char *buf, int size)
{
	return recv(context->localfd, buf, size, 0);
}

static int
http_remote_read(struct prt_context *context, char *buf, int size)
{
	return recv(context->remotefd, buf, size, 0);
}

static int
http_local_send(struct prt_context *context, char *buf, int size)
{
	return send(context->localfd, buf, size, 0);
}

static int
http_remote_send(struct prt_context *context, char *buf, int size)
{
	return send(context->remotefd, buf, size, 0);
}

void
http_set_context(struct prt_context *context)
{
	context->connect = http_connect_to;
	context->disconnect = http_disconnect;
	context->local_read = http_local_read;
	context->local_send = http_local_send;
	context->remote_read = http_remote_read;
	context->remote_send = http_remote_send;

	context->data = NULL;
}
