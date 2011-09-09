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

extern int establish_connection(char[], unsigned short);
#ifdef IPV6
extern int establish_connection6(char[], unsigned short);
#endif /* IPV6 */

extern int read_byte(int);

static int
socks5_negotiate(int fd, char *hostname, unsigned short port,
                 char *username, char *password)
{
	int i;
	char buf[515];
	unsigned char len;
	unsigned char atyp;

	buf[0] = 0x05;
	buf[1] = 0x01;
	if(username && password)
		buf[2] = 0x02;
	else
		buf[2] = 0x00;
	send(fd, buf, 3, 0);
	if(read_byte(fd) != 0x05 || read_byte(fd) != buf[2]) {
		fprintf(stderr, "Error: Bad response from SOCKS5 server\n");
		close(fd);
		return -1;
	}

	if(username && password) {
		unsigned char tmplen;

		buf[0] = 0x01;
		len = (strlen(username) > 255) ? 255 : strlen(username);
		buf[1] = len;
		memcpy(buf + 2, username, len);

		tmplen = (strlen(password) > 255) ? 255 : strlen(password);
		buf[2 + len] = tmplen;
		memcpy(buf + 3 + len, password, tmplen);

		send(fd, buf, (3 + len + tmplen), 0);

		if(read_byte(fd) != 0x01 || read_byte(fd) != 0x00) {
			fprintf(stderr, "Error: SOCKS5 authentication failed\n");
			close(fd);
			return -1;
		}
	}

	buf[0] = 0x05;
	buf[1] = 0x01;
	buf[2] = 0x00;
	buf[3] = 0x03;
	len = (strlen(hostname) > 255) ? 255 : strlen(hostname);
	buf[4] = (len & 0xff);
	memcpy(buf + 5, hostname, len);
	buf[5 + len] = (port >> 8);
	buf[6 + len] = (port & 0xff);
	send(fd, buf, (7 + len), 0);
	if(read_byte(fd) != 0x05 || read_byte(fd) != 0x00) {
		fprintf(stderr, "Error: Bad response from SOCKS5 server\n");
		close(fd);
		return -1;
	}

	read_byte(fd);
	atyp = read_byte(fd);
	if(atyp == 0x01) {
		for(i = 0; i < 4; i++)
			read_byte(fd);
	} else if(atyp == 0x03) {
		len = read_byte(fd);
		for(i = 0; i < len; i++)
			read_byte(fd);
	} else {
		fprintf(stderr, "Error: Bad response from SOCKS5 server\n");
		close(fd);
		return -1;
	}
	for(i = 0; i < 2; i++)
		read_byte(fd);

	return 0;
}

/* connect to hostname:port via a socks5 proxy; returns file descriptor */
static int
socks5_connect_to(struct prt_context *context,
                  char *hostname, unsigned short port,
                  char *username, char *password, int server_timeout)
{
	int fd;
	struct hostent *host;

	if(!proxyhost)
		return -1;

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
		fd = establish_connection(host->h_addr, proxyport);
#else
	fd = establish_connection(host->h_addr, proxyport);
#endif /* IPV6 */
	if(fd == -1) {
		fprintf(stderr, "Error: Unable to connect to SOCKS5 server %s:%u\n", proxyhost, proxyport);
		return -1;
	}

	/* set remote server socket timeout if necessary */
	if(server_timeout) {
		struct timeval timeout_val;

		timeout_val.tv_sec = server_timeout;
		timeout_val.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout_val, sizeof(timeout_val));
	}

	fprintf(stderr, "Connected to SOCKS5 server %s:%u\n", proxyhost, proxyport);

	if(socks5_negotiate(fd, hostname, port, username, password) == -1)
		return -1;

	return fd;
}

static void
socks5_disconnect(struct prt_context *context)
{
	shutdown(context->localfd, SHUT_RDWR);
	shutdown(context->remotefd, SHUT_RDWR);
	close(context->localfd);
	close(context->remotefd);
}

static int
socks5_local_read(struct prt_context *context, char *buf, int size)
{
	return recv(context->localfd, buf, size, 0);
}

static int
socks5_remote_read(struct prt_context *context, char *buf, int size)
{
	return recv(context->remotefd, buf, size, 0);
}

static int
socks5_local_send(struct prt_context *context, char *buf, int size)
{
	return send(context->localfd, buf, size, 0);
}

static int
socks5_remote_send(struct prt_context *context, char *buf, int size)
{
	return send(context->remotefd, buf, size, 0);
}

void
socks5_set_context(struct prt_context *context)
{
	context->connect = socks5_connect_to;
	context->disconnect = socks5_disconnect;
	context->local_read = socks5_local_read;
	context->local_send = socks5_local_send;
	context->remote_read = socks5_remote_read;
	context->remote_send = socks5_remote_send;

	context->data = NULL;
}
