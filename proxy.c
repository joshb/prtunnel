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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "prtunnel.h"

#ifndef NFDBITS
#define NFDBITS (sizeof(fd_set) * 8)
#endif

struct prt_context_list {
	struct prt_context **contexts;
	unsigned int num_contexts;
};

struct trusted_address {
	unsigned char address[16];
	int bitcheck;
};

struct boundsocket {
	int fd;
	struct sockaddr_in sin;
#ifdef IPV6
	struct sockaddr_in6 sin6;
#endif /* IPV6 */
	unsigned int len;
};

extern int read_byte(int fd);

/* protocol-specific functions */
extern void direct_set_context(struct prt_context *context);
#ifdef IPV6
extern void direct6_set_context(struct prt_context *context);
#endif /* IPv6 */
extern void http_set_context(struct prt_context *context);
extern void socks5_set_context(struct prt_context *context);

extern int flags;

unsigned char proxytype = PRT_HTTP;
char *proxyhost = NULL;
unsigned short proxyport = 8080;

static struct trusted_address *trusted_addresses = NULL;
static int num_trusted_addresses = 0;

static unsigned long keepalive = 0;
static char keepalive_type = PRT_KEEPALIVE_CRLF;

static struct prt_context *
prt_context_new(unsigned char type)
{
	struct prt_context *context;

	context = malloc(sizeof(struct prt_context));
	if(!context) {
		fprintf(stderr, "prt_context_new(): Memory allocation failed\n");
		return NULL;
	}

	context->localfd = -1;
	context->remotefd = -1;
	context->sockaddr_len = 0;
	context->bytes_sent = 0;
	context->bytes_rcvd = 0;
	context->data = NULL;
	context->keepalive_seconds = 0;

	switch(type) {
		default:
		case PRT_HTTP:
			http_set_context(context);
			break;
		case PRT_DIRECT:
			direct_set_context(context);
			break;
#ifdef IPV6
		case PRT_DIRECT6:
			direct6_set_context(context);
			break;
#endif /* IPV6 */
		case PRT_SOCKS5:
			socks5_set_context(context);
			break;
	}

	return context;
}

/*
 * resizes a prt_context_list.
 * returns 1 on success or 0 on error.
 */
static int
prt_context_list_resize(struct prt_context_list *list, unsigned int size)
{
	unsigned int i;
	struct prt_context **contexts;

	if(size > 0) {
		contexts = malloc(sizeof(struct prt_context *) * size);
		if(!contexts) {
			fprintf(stderr, "prt_context_list_resize(): Memory allocation failed\n");
			return 0;
		}

		for(i = 0; i < list->num_contexts && i < size; i++)
			contexts[i] = list->contexts[i];
		for(; i < size; i++)
			contexts[i] = NULL;
	} else {
		contexts = NULL;
	}

	if(list->contexts)
		free(list->contexts);
	list->contexts = contexts;
	list->num_contexts = size;

	return 1;
}

/*
 * adds a prt_context to a prt_context_list.
 * returns 1 on success or 0 on error.
 */
static int
prt_context_list_add_context(struct prt_context_list *list,
                             struct prt_context *context)
{
	unsigned int index = list->num_contexts;

	if(!prt_context_list_resize(list, list->num_contexts + 1)) {
		fprintf(stderr, "prt_context_list_add_context(): prt_context_list_resize failed\n");
		return 0;
	}

	list->contexts[index] = context;

	return 1;
}

/*
 * removes a prt_context from a prt_context_list.
 * index is an index into the prt_context_list's contexts array.
 * note that this does not free the prt_context from memory.
 */
static int
prt_context_list_remove_context(struct prt_context_list *list,
                                unsigned int index)
{
	unsigned int i;

	if(index >= list->num_contexts) {
		fprintf(stderr, "prt_context_list_remove_context(): index is too large (%u >= %u)\n", index, list->num_contexts);
		return 0;
	}

	for(i = index; i < (list->num_contexts - 1); i++)
		list->contexts[i] = list->contexts[i+1];

	prt_context_list_resize(list, list->num_contexts - 1);

	return 1;
}

static char *
get_address_string(const unsigned char *addr, unsigned char is_ipv6_address)
{
	static char s[128];
	int i;

	s[0] = '\0';
	if(is_ipv6_address) {
		char tmp[5];
		int j = 0;

		for(i = 0; i < 16; i += 2) {
			if(addr[i] == 0 && addr[i+1] == 0 && !j) {
				if(!i)
					strcat(s, "::");
				else
					strcat(s, ":");
				i += 2;
				while(addr[i] == 0 && addr[i+1] == 0 && i < 16)
					i += 2;
				j = 1;
				if(i > 15)
					break;
			}
			snprintf(tmp, 5, "%x%x", addr[i], addr[i+1]);
			strcat(s, tmp);
			if(i < 14)
				strcat(s, ":");
		}
	} else {
		snprintf(s, 128, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
	}

	return s;
}

/* sets addr pointer to location of sin_addr, and sets port to sin_port */
static void
get_ipv4_addr_and_port(struct sockaddr_in *sin,
                       unsigned char **addr, unsigned short *port)
{
	*addr = (unsigned char *)&(sin->sin_addr);
	*port = ntohs(sin->sin_port);
}

#ifdef IPV6
/* ipv6 version of above */
static void
get_ipv6_addr_and_port(struct sockaddr_in6 *sin6,
                       unsigned char **addr, unsigned short *port)
{
	*addr = (unsigned char *)&(sin6->sin6_addr);
	*port = ntohs(sin6->sin6_port);
}
#endif /* IPV6 */

void
set_keepalive_interval(unsigned int interval, char type)
{
	keepalive = interval;
	keepalive_type = type;
}

void
add_trusted_address(char *s)
{
	int i;
	struct hostent *host;
	int bitcheck = -1;
	struct trusted_address *tmp;

	if(!s)
		return;

	for(i = 0; s[i] != '/' && s[i] != '\0'; i++)
		;
	if(s[i] == '/') {
		int j = 0;
		char tmp[4];

		s[i] = '\0';
		i++;
		while(s[i] != '\0' && j < 3)
			tmp[j++] = s[i++];

		bitcheck = atoi(tmp);
		if(flags & PRT_IPV6) {
			if(bitcheck >= 128 || bitcheck < 0) {
				fprintf(stderr, "Error: Bad bitcheck number (%d) for address %s; must be 0 to 127\n", bitcheck, s);
				return;
			}
		} else if(bitcheck >= 32 || bitcheck < 0) {
			fprintf(stderr, "Error: Bad bitcheck number (%d) for address %s; must be 0 to 31\n", bitcheck, s);
			return;
		}
	}

#ifdef IPV6
	if(flags & PRT_IPV6)
		host = gethostbyname2(s, AF_INET6);
	else
#endif /* IPV6 */
		host = gethostbyname(s);
	if(!host) {
		fprintf(stderr, "Error: Unable to resolve hostname %s for trusted addresses\n", s);
		return;
	}

	tmp = realloc(trusted_addresses, sizeof(struct trusted_address) * (num_trusted_addresses + 1));
	if(!tmp) {
		fprintf(stderr, "Error: Unable to reallocate memory for trusted addresses\n");
		return;
	}
	trusted_addresses = tmp;

	i = num_trusted_addresses;
	if(flags & PRT_IPV6) {
		int j;

		for(j = 0; j < 16; j++)
			trusted_addresses[i].address[j] = host->h_addr[j];
	} else {
		int j;

		for(j = 0; j < 4; j++)
			trusted_addresses[i].address[j] = host->h_addr[j];
	}
	trusted_addresses[i].bitcheck = bitcheck;

	num_trusted_addresses++;

	if(flags & PRT_IPV6)
		fprintf(stderr, "Added trusted address %s", get_address_string((unsigned char *)host->h_addr, 1));
	else
		fprintf(stderr, "Added trusted address %s", get_address_string((unsigned char *)host->h_addr, 0));
	if(bitcheck > -1)
		fprintf(stderr, ", comparing only the first %u bits", bitcheck);
	fprintf(stderr, "\n");
}

/* return 1 if the specified address is trusted; otherwise return 0 */
static int
is_trusted_address(const unsigned char *addr)
{
	int i, j;

	if(flags & PRT_IPV6) {
		if(addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 &&
		   addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0 &&
		   addr[8] == 0 && addr[9] == 0 && addr[10] == 0 && addr[11] == 0 &&
		   addr[12] == 0 && addr[13] == 0 && addr[14] == 0 && addr[15] == 1)
			return 1;
	} else {
		if(addr[0] == 127 && addr[1] == 0 && addr[2] == 0 && addr[3] == 1)
			return 1; /* we can trust ourselves, right? right? */
	}

	for(i = 0; i < num_trusted_addresses; i++) {
		if(flags & PRT_IPV6) {
			int n = 0;

			for(j = 0; j < 16 && addr[j] == trusted_addresses[i].address[j]; j++)
				n++;

			if(n == 16)
				return 1;
		} else {
			if(addr[0] == trusted_addresses[i].address[0] &&
			   addr[1] == trusted_addresses[i].address[1] &&
			   addr[2] == trusted_addresses[i].address[2] &&
			   addr[3] == trusted_addresses[i].address[3])
				return 1;
		}

		if(trusted_addresses[i].bitcheck > -1) {
			int fullbytes, extrabits;

			fullbytes = trusted_addresses[i].bitcheck;
			extrabits = fullbytes % 8;
			fullbytes -= extrabits;
			fullbytes /= 8;

			for(j = 0; j < fullbytes; j++) {
				if(addr[j] != trusted_addresses[i].address[j])
					break;
			}
			if(j == fullbytes && (addr[j] >> (8 - extrabits)) == (trusted_addresses[i].address[j] >> (8 - extrabits)))
				return 1;
		}
	}

	return 0;
}

/*
 * if the PRT_VERBOSE bit is set, print s; if the PRT_COLOR bit
 * is set, print s in color for outgoing data
 */
static void
print_data(char *s, int len, unsigned char outgoing)
{
	int i;

	if(!(flags & PRT_VERBOSE))
		return;

	if(flags & PRT_COLOR) {
		if(outgoing)
			printf("\033[1;31m");
		else
			printf("\033[0;0m");

		for(i = 0; i < len; i++)
			putchar(s[i]);

		if(outgoing)
			printf("\033[0;0m");
	} else {
		for(i = 0; i < len; i++) {
			if(i == 0) {
				if(outgoing)
					printf(">>> ");
				else
					printf("<<< ");
			}
			putchar(s[i]);
			if(s[i] == '\n' && (len - 1) > i) {
				if(outgoing)
					printf(">>> ");
				else
					printf("<<< ");
			}
		}
	}

	fflush(stdout);
}

static struct boundsocket
tcp_bind_to(unsigned char address[4], unsigned short port)
{
	struct boundsocket bs;

	bs.fd = socket(AF_INET, SOCK_STREAM, 0);
	if(bs.fd == -1)
		return bs;

	bs.sin.sin_family = AF_INET;
	bs.sin.sin_port = htons(port);
	memcpy(&bs.sin.sin_addr, address, 4);
	bs.len = sizeof(bs.sin);

	if((bind(bs.fd, (struct sockaddr *)&bs.sin, bs.len)) == -1) {
		close(bs.fd);
		bs.fd = -1;
		return bs;
	}

	return bs;
}

#if 0
static struct boundsocket
udp_bind_to(unsigned char address[4], unsigned short port)
{
	struct boundsocket bs;

	bs.fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(bs.fd == -1)
		return bs;

	bs.sin.sin_family = AF_INET;
	bs.sin.sin_port = htons(port);
	memcpy(&bs.sin.sin_addr, address, 4);
	bs.len = sizeof(bs.sin);

	if((bind(bs.fd, (struct sockaddr *)&bs.sin, bs.len)) == -1) {
		close(bs.fd);
		bs.fd = -1;
		return bs;
	}

	return bs;
}
#endif

#ifdef IPV6
static struct boundsocket
tcp_bind_to6(unsigned char address[16], unsigned short port)
{
	struct boundsocket bs;

	bs.fd = socket(AF_INET6, SOCK_STREAM, 0);
	if(bs.fd == -1)
		return bs;

	bs.sin6.sin6_family = AF_INET6;
	bs.sin6.sin6_port = htons(port);
	memcpy(&bs.sin6.sin6_addr, address, 16);
	bs.len = sizeof(bs.sin6);

	if((bind(bs.fd, (struct sockaddr *)&bs.sin6, bs.len)) == -1) {
		close(bs.fd);
		bs.fd = -1;
		return bs;
	}

	return bs;
}

#if 0
static struct boundsocket
udp_bind_to6(unsigned char address[4], unsigned short port)
{
	struct boundsocket bs;

	bs.fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if(bs.fd == -1)
		return bs;

	bs.sin6.sin6_family = AF_INET;
	bs.sin6.sin6_port = htons(port);
	memcpy(&bs.sin.sin_addr, address, 4);
	bs.len = sizeof(bs.sin);

	if((bind(bs.fd, (struct sockaddr *)&bs.sin6, bs.len)) == -1) {
		close(bs.fd);
		bs.fd = -1;
		return bs;
	}

	return bs;
}
#endif
#endif /* IPV6 */

/*
 * accept and respond to socks commands from client,
 * return socks version
 *
 * written by ZIGLIO Frediano with minor changes by Josh Beam
 * (same for socks_method_connected function below)
 */
static int
socks_method(struct prt_context *context, char **remotehostp,
             unsigned short *remoteportp)
{
	int i;
	int local_socks = 0;
	char buf[512];
	int len;
	char *remotehost = *remotehostp;
	unsigned short remoteport = *remoteportp;

	/* socks proxy ?? */
	if (!remotehost) {
		local_socks = read_byte(context->localfd);
		switch(local_socks) {
		default:
			shutdown(context->localfd, SHUT_RDWR);
			close(context->localfd);
			return -1;
		case 5:
			len = read_byte(context->localfd);
			if (len < 0) {
				shutdown(context->localfd, SHUT_RDWR);
				close(context->localfd);
				return -1;
			}
			/* discard all methods */
			for (i=0; i < len; ++i)
				if (read_byte(context->localfd) < 0) {
					shutdown(context->localfd, SHUT_RDWR);
					close(context->localfd);
					return -1;
				}
		
			/* we support only no password */
			context->local_send(context, "\x05\x00", 2);

			/* version must be 5 */
			if ((i=read_byte(context->localfd)) != 5) {
				context->local_send(context, "\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00", 10);
				shutdown(context->localfd, SHUT_RDWR);
				close(context->localfd);
				return -1;
			}
		
			/* only connect */
			if (read_byte(context->localfd) != 1) {
				context->local_send(context, "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10);
				shutdown(context->localfd, SHUT_RDWR);
				close(context->localfd);
				return -1;
			}
			read_byte(context->localfd);
	
			switch(read_byte(context->localfd)) {
			case 1: /* ipv4 */
				for(i = 0; i < 4; ++i)
					buf[i] = read_byte(context->localfd);
				remotehost = strdup(get_address_string((unsigned char *)buf, 0));
				if(!remotehost) {
					fprintf(stderr, "Error: Memory allocation failed\n");
					return -1;
				}
				break;
			case 3: /* name */
				len = read_byte(context->localfd);
				remotehost = malloc(len+1);
				if(!remotehost) {
					fprintf(stderr, "Error: Memory allocation failed\n");
					return -1;
				}
				for(i = 0; i < len; ++i)
					remotehost[i] = read_byte(context->localfd);
				remotehost[len] = 0;
				break;
			case 4: /* ipv6 */
				for(i = 0; i < 16; ++i)
					buf[i] = read_byte(context->localfd);
				remotehost = strdup(get_address_string((unsigned char *)buf, 1));
				if(!remotehost) {
					fprintf(stderr, "Error: Memory allocation failed\n");
					return -1;
				}
				break;
			default:
				context->local_send(context, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00", 10);
				shutdown(context->localfd, SHUT_RDWR);
				close(context->localfd);
				return -1;
			}
		
			/* port */
			remoteport = read_byte(context->localfd) << 8;
			remoteport |= read_byte(context->localfd);
			break;

		case 4:
			/* only connect */
			if (read_byte(context->localfd) != 1) {
				context->local_send(context, "\x00\x5b\x00\x00\x00\x00\x00\x00", 8);
				shutdown(context->localfd, SHUT_RDWR);
				close(context->localfd);
				return -1;
			}

			remoteport = read_byte(context->localfd) << 8;
			remoteport |= read_byte(context->localfd);
			
			for(i = 0; i < 4; ++i)
				buf[i] = read_byte(context->localfd);
			remotehost = strdup(get_address_string((unsigned char *)buf, 0));
			if(!remotehost) {
				fprintf(stderr, "Error: Memory allocation failed\n");
				return -1;
			}
			
			/* discard user */
			while (read_byte(context->localfd) != 0);

			break;
		}
		
		fprintf(stderr, "Connect to %s:%d\n", remotehost, remoteport);

		*remotehostp = remotehost;
		*remoteportp = remoteport;
	}

	return local_socks;
}

static void
socks_method_connected(struct prt_context *context, int local_socks)
{
	/* !!! */
	switch (local_socks) {
	case 5:
		context->local_send(context, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10);
		break;
	case 4:
		context->local_send(context, "\x00\x5a\x00\x00\x00\x00\x00\x00", 8);
		break;
	}
}

/*
 * this function checks data from the remote server
 * and responds to IRC PINGs and such if required.
 */
static void
check_incoming_data(struct prt_context *context, char *buf, int len)
{
	int i;

	if((flags & PRT_IRC_AUTOPONG) == 0)
		return;

	for(i = 0; i < len; i++) {
		if(i == 0 || buf[i] == '\n') {
			char *s = buf + ((i == 0) ? -1 : i) + 1;

			if((flags & PRT_IRC_AUTOPONG) && strncmp(s, "PING :", 6) == 0) {
				int j;
				char tmp[512];
				char *servname;

				for(j = i + 1; s[j] != '\n' && j < len - 1; j++)
					;
				buf[j] = '\0';

				servname = buf + 6;
				snprintf(tmp, 512, "PONG :%s\n", servname);
				context->remote_send(context, tmp, strlen(tmp));
			}
		}
	}
}

static unsigned long
get_seconds()
{
#ifdef _WIN32
	static unsigned long last = -1;
	unsigned long tmp;
	unsigned long retval;

	tmp = GetTickCount() / 1000;
	if(tmp < last)
		last = tmp;
	retval = tmp - last;
	last = tmp;

	return retval;
#else
	static unsigned long last = -1;
	struct timeval tv;
	unsigned long retval;

	gettimeofday(&tv, NULL);
	if(last < 0 || tv.tv_sec < last)
		last = tv.tv_sec;
	retval = tv.tv_sec - last;
	last = tv.tv_sec;

	return retval;
#endif /* _WIN32 */
}

static struct prt_context *
prt_tcp_handle_connection(struct boundsocket *bsocket,
                          struct prt_context_list *context_list,
                          char *remotehost, unsigned short remoteport,
                          char *username, char *password, int server_timeout)
{
	unsigned char *addr;
	unsigned short port;
	int local_socks = 0;

	struct prt_context *context = prt_context_new(proxytype);
	if(!context) {
		fprintf(stderr, "Error: Couldn't create new prt_context\n");
		return NULL;
	}

#ifdef IPV6
	if(flags & PRT_IPV6) {
		context->sockaddr_len = sizeof(context->sin6);
		context->localfd = accept(bsocket->fd, (struct sockaddr *)&(context->sin6), &(context->sockaddr_len));

		get_ipv6_addr_and_port(&context->sin6, &addr, &port);
	} else
#endif /* IPV6 */
	{
		context->sockaddr_len = sizeof(context->sin);
		context->localfd = accept(bsocket->fd, (struct sockaddr *)&(context->sin), &(context->sockaddr_len));

		get_ipv4_addr_and_port(&context->sin, &addr, &port);
	}

	/* handle connection */
	if(context->localfd == -1) {
		free(context);
		return NULL;
	}

	if(!is_trusted_address(addr)) {
		fprintf(stderr, "Connection attempt from non-trusted address %s (port %u). Closing it.\n", get_address_string(addr, (flags & PRT_IPV6) != 0), port);
		close(context->localfd);
		free(context);
		return NULL;
	}

	fprintf(stderr, "Connection from %s (port %u) accepted\n", get_address_string(addr, (flags & PRT_IPV6) != 0), port);

	if(!remotehost) { /* accept socks commands if there's no predefined remotehost */
		local_socks = socks_method(context, &remotehost, &remoteport);
		if(local_socks == -1) {
			close(context->localfd);
			free(context);
			return NULL;
		}
	}

	/* connect to remote server */
	context->remotefd = context->connect(context, remotehost, remoteport, username, password, server_timeout);
	if(context->remotefd == -1) {
		fprintf(stderr, "Error: Unable to connect to remote host %s (port %u)\n", remotehost, remoteport);
		close(context->localfd);
		free(context);
		return NULL;
	}

	if(local_socks) /* connected with socks; tell socks client */
		socks_method_connected(context, local_socks);

	fprintf(stderr, "Connected to remote host %s (port %u)\n", remotehost, remoteport);
	if(!prt_context_list_add_context(context_list, context)) {
		free(context);
		return NULL;
	}

	return context;
}

#ifdef _WIN32
static void
bzero(void *p, unsigned int size)
{
	unsigned int i;

	for(i = 0; i < size; i++)
		((unsigned char *)p)[i] = 0;
}
#endif /* _WIN32 */

static int
prt_tcp_loop(unsigned char *localaddr, unsigned short localport,
             char *remotehost, unsigned short remoteport,
             char *username, char *password, int timeout, int server_timeout)
{
	struct boundsocket bsocket;
	struct prt_context_list context_list;
	fd_set *readfds = NULL;
	unsigned int readfds_size = 0, old_readfds_size = 0;
	unsigned char *addr;
	unsigned short port;
	unsigned int i;
	int tmp;
	int largest;
	struct timeval tv;

	context_list.contexts = NULL;
	context_list.num_contexts = 0;

#ifdef IPV6
	if(flags & PRT_IPV6)
		bsocket = tcp_bind_to6(localaddr, localport);
	else
#endif /* IPV6 */
		bsocket = tcp_bind_to(localaddr, localport);
	if(bsocket.fd == -1) {
		fprintf(stderr, "Error: Unable to bind socket. The port you specified (%u) may be reserved or already in use.\n", localport);
		return -1;
	}

	if(listen(bsocket.fd, 0) == -1) {
		fprintf(stderr, "Error: Unable to listen to socket\n");
		close(bsocket.fd);
		return -1;
	}

	fprintf(stderr, "Waiting for connection to port %u...\n", localport);

	/*
	 * if not in daemon mode, we just wait for one connection
	 * here, and finish up when the connection is closed
	 */
	if(!(flags & PRT_DAEMON)) {
		struct prt_context *context = NULL;
		while(!context) {
			context = prt_tcp_handle_connection(&bsocket, &context_list, remotehost, remoteport, username, password, server_timeout);
			if(context) {
				context->keepalive_seconds = get_seconds();

				/* set client socket timeout if necessary */
				if(timeout) {
					struct timeval timeout_val;

					timeout_val.tv_sec = timeout;
					timeout_val.tv_usec = 0;
					setsockopt(context->localfd, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout_val, sizeof(timeout_val));
				}
			}
		}
	}

	/* determine largest fd */
	if(flags & PRT_DAEMON)
		largest = bsocket.fd;
	else
		largest = -1;
	for(i = 0; i < context_list.num_contexts; i++) {
		struct prt_context *context = context_list.contexts[i];
		if(!context)
			continue;

		if(context->localfd > largest)
			largest = context->localfd;
		if(context->remotefd > largest)
			largest = context->remotefd;
	}

	/* allocate memory for fd_set */
	readfds_size = ((largest + NFDBITS) / NFDBITS) * sizeof(fd_set);
	old_readfds_size = readfds_size;
	readfds = malloc(readfds_size);
	if(!readfds) {
		fprintf(stderr, "Error: Memory allocation failed\n");
		return -1;
	}

	/* add bound socket fd to fd_set */
	bzero(readfds, readfds_size);
	if(flags & PRT_DAEMON)
		FD_SET(bsocket.fd, readfds);
	/* add each fd from every context in list */
	for(i = 0; i < context_list.num_contexts; i++) {
		struct prt_context *context = context_list.contexts[i];
		if(!context)
			continue;

		FD_SET(context->localfd, readfds);
		FD_SET(context->remotefd, readfds);
	}

	tv.tv_sec = 1; /* one second timeout for select call */
	tv.tv_usec = 0;
	while((tmp = select(largest + 1, readfds, NULL, NULL, &tv)) > -1) {
		/* handle new connections */
		if(FD_ISSET(bsocket.fd, readfds)) {
			struct prt_context *context = prt_tcp_handle_connection(&bsocket, &context_list, remotehost, remoteport, username, password, server_timeout);
			if(context) {
				context->keepalive_seconds = get_seconds();

				/* set client socket timeout if necessary */
				if(timeout) {
					struct timeval timeout_val;

					timeout_val.tv_sec = timeout;
					timeout_val.tv_usec = 0;
					setsockopt(context->localfd, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout_val, sizeof(timeout_val));
				}
			}
		}

		/* loop through context list and handle any pending data */
		for(i = 0; i < context_list.num_contexts; i++) {
			struct prt_context *context = context_list.contexts[i];
			if(!context)
				continue;

			/* send keepalive */
			context->keepalive_seconds += get_seconds();
			if(keepalive && context->keepalive_seconds >= keepalive) {
				unsigned char s[2];

				context->keepalive_seconds = 0;

				switch(keepalive_type) {
					default:
					case PRT_KEEPALIVE_CRLF:
						s[0] = '\r';
						s[1] = '\n';
						context->remote_send(context, (char *)s, 2);
						break;
					case PRT_KEEPALIVE_TELNET:
						s[0] = 255;
						s[1] = 241;
						context->remote_send(context, (char *)s, 2);
						break;
				}
			}

			/* send data from client to remote server */
			if(FD_ISSET(context->localfd, readfds)) {
				char buf[512];

				tmp = context->local_read(context, buf, 512);
				if(tmp <= 0) { /* connection closed */
					prt_context_list_remove_context(&context_list, i);
					context->disconnect(context);
#ifdef IPV6
					if(flags & PRT_IPV6)
						get_ipv6_addr_and_port(&context->sin6, &addr, &port);
					else
#endif /* IPV6 */
						get_ipv4_addr_and_port(&context->sin, &addr, &port);
					fprintf(stderr, "Connection from %s (port %u) closed - %u bytes sent, %u bytes received\n", get_address_string(addr, (flags & PRT_IPV6) != 0), port, context->bytes_sent, context->bytes_rcvd);
					free(context);
					if(!(flags & PRT_DAEMON)) {
						shutdown(bsocket.fd, SHUT_RDWR);
						close(bsocket.fd);
						return 0;
					}
					continue;
				}

				context->remote_send(context, buf, tmp);
				context->bytes_sent += tmp;

				print_data(buf, tmp, 1);
			}

			/* send data from remote server to client */
			if(FD_ISSET(context->remotefd, readfds)) {
				char buf[512];

				tmp = context->remote_read(context, buf, 512);
				if(tmp <= 0) { /* connection closed */
					prt_context_list_remove_context(&context_list, i);
					context->disconnect(context);
#ifdef IPV6
					if(flags & PRT_IPV6)
						get_ipv6_addr_and_port(&context->sin6, &addr, &port);
					else
#endif /* IPV6 */
						get_ipv4_addr_and_port(&context->sin, &addr, &port);
					fprintf(stderr, "Connection from %s (port %u) closed - %u bytes sent, %u bytes received\n", get_address_string(addr, (flags & PRT_IPV6) != 0), port, context->bytes_sent, context->bytes_rcvd);
					free(context);
					if(!(flags & PRT_DAEMON)) {
						shutdown(bsocket.fd, SHUT_RDWR);
						close(bsocket.fd);
						return 0;
					}
					continue;
				}

				context->local_send(context, buf, tmp);
				context->bytes_rcvd += tmp;

				print_data(buf, tmp, 0);

				/* check_incoming_data must come last, since it might modify buf */
				check_incoming_data(context, buf, tmp);
			}
		}

		/* determine largest fd */
		if(flags & PRT_DAEMON)
			largest = bsocket.fd;
		else
			largest = -1;
		for(i = 0; i < context_list.num_contexts; i++) {
			struct prt_context *context = context_list.contexts[i];
			if(!context)
				continue;

			if(context->localfd > largest)
				largest = context->localfd;
			if(context->remotefd > largest)
				largest = context->remotefd;
		}

		/* allocate memory for fd_set */
		readfds_size = ((largest + NFDBITS) / NFDBITS) * sizeof(fd_set);
		if(readfds_size != old_readfds_size) {
			if(readfds)
				free(readfds);
			readfds = malloc(readfds_size);
			if(!readfds) {
				fprintf(stderr, "Error: Memory allocation failed\n");
				return -1;
			}
			old_readfds_size = readfds_size;
		}

		/* add bound socket fd to fd_set */
		bzero(readfds, readfds_size);
		if(flags & PRT_DAEMON)
			FD_SET(bsocket.fd, readfds);
		/* add each fd from every context in list */
		for(i = 0; i < context_list.num_contexts; i++) {
			struct prt_context *context = context_list.contexts[i];
			if(!context)
				continue;

			FD_SET(context->localfd, readfds);
			FD_SET(context->remotefd, readfds);
		}

		tv.tv_sec = 1; /* one second timeout for select call */
		tv.tv_usec = 0;
	}

	close(bsocket.fd);
	return 0;
}

int
prt_proxy(unsigned char *localaddr, unsigned short localport,
          char *remotehost, unsigned short remoteport,
          char *username, char *password,
          int timeout, int server_timeout)
{
#ifndef _WIN32
	if(flags & PRT_DAEMON) { /* we're a daemon, so fork and return */
		int daemonpid;

		daemonpid = fork();
		if(daemonpid == -1) {
			fprintf(stderr, "Error: Couldn't fork daemon process\n");
			return -1;
		} else if(daemonpid) {
			fprintf(stderr, "prtunnel daemon started\n");
			return 0;
		}

		setsid();
		chdir("/");
	}
#endif /* _WIN32 */

	return prt_tcp_loop(localaddr, localport, remotehost, remoteport, username, password, timeout, server_timeout);
}
