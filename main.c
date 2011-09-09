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

#define VERSION "0.2.7"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#	include "getopt.h"
#else
#	include <termios.h>
#endif /* _WIN32 */
#ifdef __GLIBC__
#include <getopt.h>
#endif
#include "prtunnel.h"

#define USERNAME_MAX 256
#define PASSWORD_MAX 256

unsigned int flags = 0;

extern unsigned char proxytype;
extern char *proxyhost;
extern unsigned short proxyport;

void show_usage_message(char *, FILE *);
void show_version_message();

extern void set_keepalive_interval(unsigned int, char);
extern void add_trusted_address(char *);
extern int prt_proxy(unsigned char *, unsigned short, char *, unsigned short, char *, char *, int, int);

static char username[USERNAME_MAX];
static char password[PASSWORD_MAX];

static void username_password_prompt();

#ifndef _WIN32
static int terminal_echo_off(int);
static int terminal_echo_on(int);
#endif /* _WIN32 */

int
main(int argc, char *argv[])
{
	int i, j;
	int ch;
	int localport;
	char *remotehost;
	int remoteport;
	unsigned char *localaddrp;
	static unsigned char localaddr[4];
#ifdef IPV6
	static unsigned char localaddr6[16];
#endif /* IPV6 */
	int timeout = 0, server_timeout = 0;
	int password_prompt = 0;
#ifdef _WIN32
	WSADATA wsadata;
#endif /* _WIN32 */

	username[0] = '\0';
	password[0] = '\0';

	for(i = 0; i < 4; i++)
		localaddr[i] = 0;
#ifdef IPV6
	for(i = 0; i < 16; i++)
		localaddr6[i] = 0;
#endif /* IPV6 */

	for(i = 1; i < argc; i++) {
		if(strcmp(argv[i], "--help") == 0) {
			show_usage_message(argv[0], stdout);
			return 0;
		} else if(strcmp(argv[i], "--version") == 0) {
			show_version_message();
			return 0;
		} else if(strcmp(argv[i], "--http-1.0") == 0) {
			flags |= PRT_HTTP_1_0;

			for(j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];
			argc--;
		} else if(strcmp(argv[i], "--password-prompt") == 0) {
			password_prompt = 1;

			for(j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];
			argc--;
		} else if(strcmp(argv[i], "--irc-auto-pong") == 0) {
			flags |= PRT_IRC_AUTOPONG;

			for(j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];
			argc--;
		} else if(strcmp(argv[i], "--telnet-keep-alive") == 0) {
			unsigned long keepalive;

			if(i + 1 >= argc) {
				show_usage_message(argv[0], stderr);
				return 1;
			}

			keepalive = atoi(argv[i + 1]);
			set_keepalive_interval(keepalive, PRT_KEEPALIVE_TELNET);

			for(j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];
			for(j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];
			argc -= 2;
		} else if(strcmp(argv[i], "--crlf-keep-alive") == 0) {
			unsigned int keepalive;

			if(i + 1 >= argc) {
				show_usage_message(argv[0], stderr);
				return 1;
			}

			keepalive = atoi(argv[i + 1]);
			set_keepalive_interval(keepalive, PRT_KEEPALIVE_CRLF);

			for(j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];
			for(j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];
			argc -= 2;
		} else if(strcmp(argv[i], "--max-processes") == 0) {
			if(i + 1 >= argc) {
				show_usage_message(argv[0], stderr);
				return 1;
			}

			fprintf(stderr, "Note: Instances of prtunnel now use only one process for handling all connections, so the --max-processes option is obsolete.\n");

			for(j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];
			for(j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];
			argc -= 2;
		} else if(strcmp(argv[i], "--timeout") == 0) {
			if(i + 1 >= argc) {
				show_usage_message(argv[0], stderr);
				return 1;
			}

			timeout = atoi(argv[i + 1]);

			for(j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];
			for(j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];
			argc -= 2;
		} else if(strcmp(argv[i], "--server-timeout") == 0) {
			if(i + 1 >= argc) {
				show_usage_message(argv[0], stderr);
				return 1;
			}

			server_timeout = atoi(argv[i + 1]);

			for(j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];
			for(j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];
			argc -= 2;
		} else if(strncmp(argv[i], "--", 2) == 0) {
			fprintf(stderr, "Invalid option `%s'. Run %s --help for more information.\n", argv[i], argv[0]);
			return 1;
		}
	}

	while((ch = getopt(argc, argv, "hvDVc6qt:H:P:T:u:p:")) != -1) {
		switch(ch) {
			case 'h':
				show_usage_message(argv[0], stdout);
				return 0;
			case 'v':
				show_version_message();
				return 0;
			case 'D':
				flags |= PRT_DAEMON;
				break;
			case 'V':
				flags |= PRT_VERBOSE;
				break;
			case 'c':
				flags |= PRT_COLOR;
				break;
			case '6':
#ifdef IPV6
				flags |= PRT_IPV6;
#else
				fprintf(stderr, "Can't use IPv6; prtunnel not compiled with IPv6 support\n");
				return 1;
#endif /* IPV6 */
				break;
			case 't':
				if(strcmp(optarg, "direct") == 0) {
					proxytype = PRT_DIRECT;
				} else if(strcmp(optarg, "direct6") == 0) {
#ifdef IPV6
					proxytype = PRT_DIRECT6;
#else
					fprintf(stderr, "Can't use direct6 mode; prtunnel not compiled with IPv6 support\n");
					return 1;
#endif /* IPV6 */
				} else if(strcmp(optarg, "http") == 0) {
					proxytype = PRT_HTTP;
				} else if(strcmp(optarg, "socks5") == 0) {
					proxytype = PRT_SOCKS5;
					proxyport = 1080;
				} else {
					fprintf(stderr, "Invalid proxy type `%s'\nRun `%s --help' for usage information.\n", optarg, argv[0]);
					return 1;
				}
				break;
			case 'H':
				proxyhost = optarg;
				break;
			case 'P':
				proxyport = atoi(optarg);
				break;
			case 'T':
				add_trusted_address(optarg);
				break;
			case 'u':
				snprintf(username, USERNAME_MAX, optarg);
				break;
			case 'p':
				snprintf(password, PASSWORD_MAX, optarg);
				break;
		}
	}

	if((argc - optind) != 3 && (argc - optind) != 1) {
		if((argc - optind) == 0) {
			show_version_message();
			putchar('\n');
			show_usage_message(argv[0], stdout);
		} else {
			show_usage_message(argv[0], stderr);
		}
		return 1;
	}

	if(!proxyhost && proxytype != PRT_DIRECT && proxytype != PRT_DIRECT6) {
		fprintf(stderr, "No proxy hostname has been specified. You can specify one with the -H option.\nRun `%s --help' for more information.\n", argv[0]);
		return 1;
	}

	localport = atoi(argv[optind]);
	if((argc - optind) == 3) {
		remotehost = argv[optind + 1];
		remoteport = atoi(argv[optind + 2]);
	} else {
		remotehost = NULL;
		remoteport = 0;
	}

#ifdef IPV6
	if(flags & PRT_IPV6)
		localaddrp = localaddr6;
	else
		localaddrp = localaddr;
#else
		localaddrp = localaddr;
#endif /* IPV6 */

	if(password_prompt)
		username_password_prompt();

#ifdef _WIN32
	WSAStartup(MAKEWORD(2,0), &wsadata);
#endif /* _WIN32 */

	if(strlen(username) < 1 && strlen(password) < 1) {
		if(prt_proxy(localaddrp, localport, remotehost, remoteport, NULL, NULL, timeout, server_timeout) == -1) {
			fprintf(stderr, "prtunnel: Exiting because of error\n");
			return 1;
		}
	} else {
		if(prt_proxy(localaddrp, localport, remotehost, remoteport, username, password, timeout, server_timeout) == -1) {
			fprintf(stderr, "prtunnel: Exiting because of error\n");
			return 1;
		}
	}

	return 0;
}

void
show_usage_message(char *name, FILE *fp)
{
	fprintf(fp, "usage: %s [options] <local port> [<remote host> <remote port>]\n\n(If run without the <remote host> and <remote port> options, prtunnel will\naccept SOCKS4/SOCKS5 commands to determine the remote server to connect to.)\n\n", name);
	fprintf(fp, "options:\n");
	fprintf(fp, "  -D\t\t\tRun as a daemon. prtunnel will run in the background\n\t\t\tand accept multiple TCP connections with this option.\n");
	fprintf(fp, "  -V\t\t\tVerbose output\n");
	fprintf(fp, "  -c\t\t\tUse color to differentiate between incoming\n\t\t\tand outgoing data in verbose output\n");
	fprintf(fp, "  -6\t\t\tUse IPv6; prtunnel must be compiled with IPv6 support\n");
	fprintf(fp, "  -t <proxy type>\tSet proxy type. Valid types are http (default),\n\t\t\tsocks5, direct, direct6\n");
	fprintf(fp, "  -H <proxy host>\tSet proxy server hostname\n");
	fprintf(fp, "  -P <proxy port>\tSet proxy server port; defaults are 8080 for http,\n\t\t\t1080 for socks5\n");
	fprintf(fp, "  -T <address>\t\tAdd a trusted address. For security reasons, only\n\t\t\t127.0.0.1 is trusted by default. See the prtunnel\n\t\t\tman page or README file for more information.\n");
	fprintf(fp, "  -u <username>\t\tSet authentication username\n");
	fprintf(fp, "  -p <password>\t\tSet authentication password\n");
	fprintf(fp, "  --password-prompt\tPrompt for proxy username and password\n");
	fprintf(fp, "  --http-1.0\t\tUse HTTP/1.0 instead of HTTP/1.1 for HTTP connections\n");
	fprintf(fp, "  --telnet-keep-alive <interval>\n\t\t\tCauses prtunnel to send keep-alive data at the\n\t\t\tspecified interval, using the telnet NOP command\n");
	fprintf(fp, "  --crlf-keep-alive <interval>\n\t\t\tCauses prtunnel to send keep-alive data at the\n\t\t\tspecified interval, using a CRLF\n");
	fprintf(fp, "  --irc-auto-pong\tCauses prtunnel to automatically respond to PING\n\t\t\tcommands sent by IRC servers\n");
	fprintf(fp, "  --timeout <time>\tAllows you to set a client socket timeout; if no data\n\t\t\tis recieved from the client for <time> seconds, the\n\t\t\tconnection will be closed\n");
	fprintf(fp, "  --server-timeout <time>\n\t\t\tAllows you to set a server socket timeout; if no data\n\t\t\tis recieved from the remote host for <time> seconds,\n\t\t\tthe connection will be closed\n");
	fprintf(fp, "  -h, --help\t\tShow this help message\n");
	fprintf(fp, "  -v, --version\t\tShow version information\n");
}

void
show_version_message()
{
	printf("prtunnel "VERSION"\n");
	printf("The latest version can be found at http://joshbeam.com/software/prtunnel.php\n");
	printf("Copyright (C) 2002-2006 Josh A. Beam <josh@joshbeam.com>\n");
	printf("There is NO WARRANTY for this software.\n");
}

/*
 * Username/password prompt code (including the terminal_echo_off
 * and terminal_echo_on functions) written by Diaconescu Bogdan,
 * with some small modifications by Josh Beam.
 */
static void
username_password_prompt()
{
	printf("Proxy username: ");
	if (fgets(username, USERNAME_MAX, stdin) == NULL || strlen(username) < 1)
	{
		fprintf(stderr, "Error: Couldn't read username from standard input\n");
		exit(1);
	}
	/*
	 * Get rid of the new line character.
	 */
	username[strlen(username) - 1] = 0;

	printf("Proxy password: ");

#ifndef _WIN32
	terminal_echo_off(fileno(stdin));
#endif /* _WIN32 */
	if (fgets(password, PASSWORD_MAX, stdin) == NULL || strlen(password) < 1)
	{
		fprintf(stderr, "Error: Couldn't read password from standard input\n");
		exit(1);
	}
#ifndef _WIN32
	terminal_echo_on(fileno(stdin));
#endif /* _WIN32 */

	printf("\n");

	/*
	 * Get rid of the new line character.
	 */
	password[strlen(password) - 1] = 0;
}

#ifndef _WIN32
static int
terminal_echo_off(int fd)
{
	struct termios term;

	if (isatty(fd) == 0)
	{
#ifdef DEBUG
		printf("the file %i is not a terminal\n", fd);
#endif /* DEBUG */
		return -1;
	}
	
	if (tcgetattr(fd, &term) < 0)
	{
#ifdef DEBUG
		perror("tcgetattr: ");	
#endif /* DEBUG */
		return -1;
	}

	term.c_lflag &= ~ECHO;

	if (tcsetattr(fd, TCSANOW, &term) < 0)
	{
#ifdef DEBUG
		perror("tcsetattr: ");
#endif /* DEBUG */
		return -1;
	}

	return 0;
}

static int
terminal_echo_on(int fd)
{
	struct termios term;

	if (isatty(fd) == 0)
	{
#ifdef DEBUG
		printf("the file %i is not a terminal\n", fd);
#endif /* DEBUG */
		return -1;
	}
	
	if (tcgetattr(fd, &term) < 0)
	{
#ifdef DEBUG
		perror("tcgetattr: ");	
#endif /* DEBUG */
		return -1;
	}

	term.c_lflag |= ECHO;

	if (tcsetattr(fd, TCSANOW, &term) < 0)
	{
#ifdef DEBUG
		perror("tcsetattr: ");
#endif /* DEBUG */
		return -1;
	}

	return 0;
}
#endif /* _WIN32 */
