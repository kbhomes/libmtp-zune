/**
 * \file mtpz-data.h
 * Data used by the MTPZ process, including certificates and keys.
 *
 * Copyright (C) 2011-2012 Sajid Anwar <sajidanwar94@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * <code>
 * #include <mtpz-data.h>
 * </code>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* The ~/.mtpz-data file contains all four necessary pieces of data:
 *
 *   public exponent
 *   modulus
 *   private key
 *   certificate data
 *
 * These four pieces of data are each stored in hex representation,
 * separated by newline characters.
*/

int use_mtpz;

unsigned char *MTPZ_PUBLIC_EXPONENT;
unsigned char *MTPZ_MODULUS;
unsigned char *MTPZ_PRIVATE_KEY;
char *MTPZ_CERTIFICATES;

// Strip the trailing newline from fgets().
static char *fgets_strip(char * str, int num, FILE * stream)
{
	char *result = str;

	if ((result = fgets(str, num, stream)))
	{
		size_t newlen = strlen(result);

		if (result[newlen - 1] == '\n') 
			result[newlen - 1] = '\0';
	}

	return result;
}

static char *hex_to_bytes(char *hex, size_t len)
{
	if (len % 2)
		return NULL;

	char *bytes = malloc(len / 2);
	unsigned int u;
	int i = 0;

	while (i < len && sscanf(hex + i, "%2x", &u) == 1)
	{
		bytes[i / 2] = u;
		i += 2;
	}

	return bytes;
}

static int mtpz_loaddata()
{	
	char *home = getenv("HOME");
	if (!home)
	{
		printf("Error: Unable to determine user's home directory.\n");
		return -1;	
	}

	int plen = strlen(home) + strlen("/.mtpz-data") + 1;
	char path[plen];
	sprintf(path, "%s/.mtpz-data", home);

	FILE *fdata = fopen(path, "r");
	if (!fdata)
	{
		printf("Error: Unable to open ~/.mtpz-data for reading.\n");
		return -1;
	}

	// Should only be six characters in length, but fgets will encounter a newline and stop.
	MTPZ_PUBLIC_EXPONENT = (unsigned char *)fgets_strip((char *)malloc(8), 8, fdata);
	if (!MTPZ_PUBLIC_EXPONENT)
	{
		printf("Error: Unable to read MTPZ public exponent from ~/.mtpz-data\n");
		return -1;
	}

	// Should only be 256 characters in length, but fgets will encounter a newline and stop.
	MTPZ_MODULUS = (unsigned char *)fgets_strip((char *)malloc(260), 260, fdata);
	if (!MTPZ_MODULUS)
	{
		printf("Error: Unable to read MTPZ modulus from ~/.mtpz-data\n");
		return -1;
	}

	// Should only be 256 characters in length, but fgets will encounter a newline and stop.
	MTPZ_PRIVATE_KEY = (unsigned char *)fgets_strip((char *)malloc(260), 260, fdata);
	if (!MTPZ_PRIVATE_KEY)
	{
		printf("Error: Unable to read MTPZ private key from ~/.mtpz-data\n");
		return -1;
	}

	// Should only be 1258 characters in length, but fgets will encounter the end of the file and stop.
	char *hexcerts = fgets_strip((char *)malloc(1260), 1260, fdata);
	if (!hexcerts)
	{
		printf("Error: Unable to read MTPZ certificates from ~/.mtpz-data\n");
		return -1;
	}
	MTPZ_CERTIFICATES = hex_to_bytes(hexcerts, strlen(hexcerts));
	if (!MTPZ_CERTIFICATES)
	{
		printf("Error: Unable to parse MTPZ certificates from ~/.mtpz-data\n");
		return -1;
	}

	return 0;
}
