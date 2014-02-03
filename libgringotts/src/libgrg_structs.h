/*  libGringotts - generic data encoding (crypto+compression) library
 *  (c) 2002, Germano Rizzo <mano@pluto.linux.it>
 *
 *  libgrg_structs.h - header file for libgrg_structs.c
 *  Author: Germano Rizzo
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef LIBGRG_STRUCTS_H
#define LIBGRG_STRUCTS_H

#include "libgringotts.h"
#include <stdio.h>
#include <mcrypt.h>

#define HEADER_LEN	3

struct _grg_context
{
	int rnd;
	unsigned char header[3];
	grg_crypt_algo crypt_algo;
	grg_hash_algo hash_algo;
	grg_comp_algo comp_algo;
	grg_comp_ratio comp_lvl;
	grg_security_lvl sec_lvl;
};

struct _grg_key
{
	char key_192_ripe[24];
	char key_256_ripe[32];
	char key_192_sha[24];
	char key_256_sha[32];
};

struct _grg_tmpfile
{
	int tmpfd;

	int dKey;
	unsigned char *key;
	int dIV;
	unsigned char *IV;

	MCRYPT crypt;

	unsigned int rwmode;
};

#endif
