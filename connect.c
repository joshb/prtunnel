/*
 * Copyright (C) 2002-2005 Josh A. Beam
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

/* read one byte from fd and return it */
int
read_byte(int fd)
{
	unsigned char c;

	if(recv(fd, &c, 1, 0) != -1)
		return c;

	return -1;
}

/*
 * connect to address:port; this function is used by the
 * protocol-specific connect_to functions to connect to
 * the proxy server
 */
int
establish_connection(unsigned char address[4], unsigned short port)
{
	int fd;
	struct sockaddr_in sin;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd == -1)
		return -1;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	memcpy(&sin.sin_addr, address, 4);

	if(connect(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
		close(fd);
		return -1;
	}

	return fd;
}

/* ipv6 version of above */
#ifdef IPV6
int
establish_connection6(unsigned char address[16], unsigned short port)
{
	int fd;
	struct sockaddr_in6 sin;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if(fd == -1)
		return -1;

	sin.sin6_family = AF_INET6;
	sin.sin6_port = htons(port);
	memcpy(&sin.sin6_addr, address, 16);

	if(connect(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
		close(fd);
		return -1;
	}

	return fd;
}
#endif /* IPV6 */
