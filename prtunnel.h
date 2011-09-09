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

/* flags */
#define PRT_VERBOSE 0x1
#define PRT_COLOR   0x2
#define PRT_DAEMON	0x4
#define PRT_IPV6    0x8
#define PRT_IRC_AUTOPONG 0x10
#define PRT_HTTP_1_0     0x20

/* proxy types */
#define PRT_DIRECT     0
#define PRT_DIRECT6    1
#define PRT_HTTP       2
#define PRT_SOCKS5     3

/* keep-alive types */
#define PRT_KEEPALIVE_TELNET 0
#define PRT_KEEPALIVE_CRLF   1

#ifdef _WIN32
#	include <winsock2.h>
#	define SHUT_RDWR SD_BOTH
#	define close(s) closesocket(s)
#	define snprintf _snprintf
#else
#	include <unistd.h>
#	include <sys/time.h>
#	include <sys/socket.h>
#	include <netinet/in.h>
#	include <netdb.h>
#endif /* _WIN32 */

struct prt_context {
	/* pointers to protocol-specific functions */
	int (*connect)(struct prt_context *context, char *hostname, unsigned short port, char *username, char *password, int server_timeout);
	void (*disconnect)(struct prt_context *context);
	int (*local_read)(struct prt_context *context, char *buf, int size);
	int (*local_send)(struct prt_context *context, char *buf, int size);
	int (*remote_read)(struct prt_context *context, char *buf, int size);
	int (*remote_send)(struct prt_context *context, char *buf, int size);

	struct sockaddr_in sin;
#ifdef IPV6
	struct sockaddr_in6 sin6;
#endif /* IPV6 */
	unsigned int sockaddr_len;

	int localfd; /* client socket */
	int remotefd; /* server socket */
	unsigned int bytes_sent;
	unsigned int bytes_rcvd;
	void *data; /* some protocols may require extra data, so we
	               include this pointer for them to keep track of it */

	unsigned long keepalive_seconds;
};
