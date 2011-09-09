/*
 * Copyright (C) 2006 Josh A. Beam
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

/*
 * This is a simple getopt implementation for use by prtunnel
 * on win32 systems. Note that it only supports the features
 * that prtunnel actually uses, so it doesn't have an opterr
 * variable, for example.
 */

#ifdef _WIN32
#include <stdio.h>
#include <string.h>
#include "getopt.h"

#ifndef NULL
#define NULL 0
#endif

int optind = 1;
char *optarg = NULL;

/*
 * if opt is an option found in optstring, return opt. otherwise,
 * return -1. if opt is valid and it has an argument, set the int
 * pointed to by has_argument to 1. otherwise, set it 0.
 */
static char
get_matching_option(char opt, const char *optstring, int *has_argument)
{
	int i;

	for(i = 0; i < strlen(optstring); i++) {
		if(opt == optstring[i]) {
			/* if there's a colon after this character, the option has
			 * an argument */
			if((i + 1) < strlen(optstring) && optstring[i+1] == ':')
				*has_argument = 1;
			else
				*has_argument = 0;

			return opt;
		}
	}

	return -1;
}

/*
 * permutes argv so that the argument at the specified
 * index appears at the end of the array.
 */
static void
permute_arguments(int argc, char *argv[], int index)
{
	int i;
	char *tmp = argv[index];

	for(i = index; i < (argc - 1); i++)
		argv[i] = argv[i+1];

	argv[argc-1] = tmp;
}

int
getopt(int argc, char *argv[], const char *optstring)
{
	static int current_arg = 1;
	static int current_char = 1;
	static int loop_argc = -1;
	int i;

	/* loop_argc is used instead of argc directly so that the
	 * permuted arguments are not scanned more than once. this
	 * is done by decrementing loop_argc every time an
	 * argument is permuted. note that the permute_arguments
	 * function still needs to be given the actual argc.*/
	if(loop_argc < 0)
		loop_argc = argc;

	if(current_arg >= argc) /* past end of arguments */
		return -1;

	/* loop through each argument */
	for(i = current_arg; i < loop_argc; i++, current_arg++) {
		char opt;
		int has_argument;

		if(*argv[i] != '-') { /* not an option string */
			permute_arguments(argc, argv, i);
			i--; /* arguments have been re-arranged, so the one at
				  * this index needs to be looked at again */
			current_arg--;
			loop_argc--;
			continue;
		} else if(current_char == 1) {
			optind++;
		}

		if(current_char >= strlen(argv[i])) { /* past end of argument */
			current_char = 1;
			continue;
		}

		/* if the current character matches an option in the option string,
		 * return the character. otherwise, return '?' */
		opt = get_matching_option(argv[i][current_char], optstring, &has_argument);
		if(opt != -1) {
			/* if the option has an argument, set optarg pointer. if
			 * the argument is missing, return ':' */
			if(has_argument) {
				/* if there are any characters after the current one
				 * in this argument, use those as the option argument.
				 * otherwise, use the next argument */
				if(current_char < (strlen(argv[i]) - 1)) {
					optarg = argv[i] + current_char + 1;
					current_arg++;    /* set past the option argument */
					current_char = 0; /* reset */
				} else {
					current_arg += 2; /* set past the option argument */
					current_char = 0; /* reset */
					optind++;
					if((i + 1) < loop_argc) {
						optarg = argv[i + 1];
					} else {
						optarg = NULL;
						current_char++;
						return ':';
					}
				}
			}

			current_char++;
			return (int)opt;
		} else {
			current_char++;
			return '?';
		}
	}

#ifdef DEBUG_GETOPT
	printf("argv:");
	for(i = 0; i < argc; i++)
		printf(" %s", argv[i]);
	printf("\n");
#endif /* DEBUG_GETOPT */

	/* reached end of arguments */
	return -1;
}
#endif /* _WIN32 */
