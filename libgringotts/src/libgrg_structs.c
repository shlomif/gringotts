/*  libGringotts - generic data encoding (crypto+compression) library
 *  (c) 2002, Germano Rizzo <mano@pluto.linux.it>
 *
 *  libgrg_structs.c - functions to manage the various libgrg structs
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

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include <mhash.h>

#include "config.h"
#include "libgrg_structs.h"
#include "libgrg_utils.h"
#include "libgringotts.h"

static int
reinit_random (GRG_CTX gctx)
{
#ifdef HAVE__DEV_RANDOM
	if (!gctx)
		return 0;

	close (gctx->rnd);

	if (gctx->sec_lvl == GRG_SEC_PARANOIA)
		gctx->rnd = open ("/dev/random", O_RDONLY);
	else
		gctx->rnd = open ("/dev/urandom", O_RDONLY);

	if (gctx->rnd < 3)
	{
		close (gctx->rnd);
		return 0;
	}
#else
#warning compiling without /dev/random
	srandom ((unsigned int) time (NULL));
#endif

	return 1;
}

GRG_CTX
grg_context_initialize (const unsigned char *header,
			const grg_crypt_algo crypt_algo,
			const grg_hash_algo hash_algo,
			const grg_comp_algo comp_algo,
			const grg_comp_ratio comp_lvl,
			const grg_security_lvl sec_lvl)
{
	GRG_CTX ret = (GRG_CTX) malloc (sizeof (struct _grg_context));
		
	if (!ret)
		return NULL;

	ret->rnd = -1;		//dummy
#ifdef HAVE__DEV_RANDOM
	if (!reinit_random (ret))
	{
		free (ret);
		return NULL;
	}
#endif

	if (!header || (strlen (header) != HEADER_LEN))
	{
#ifdef HAVE__DEV_RANDOM
		close (ret->rnd);
#endif
		free (ret);
		return NULL;
	}

	memcpy (ret->header, header, HEADER_LEN);
	ret->crypt_algo = crypt_algo;
	ret->hash_algo = hash_algo;
	ret->comp_algo = comp_algo;
	ret->comp_lvl = comp_lvl;
	ret->sec_lvl = sec_lvl;

	return ret;
}

GRG_CTX
grg_context_initialize_defaults (const unsigned char *header)
{
	return grg_context_initialize (header, GRG_SERPENT, GRG_RIPEMD_160,
				       GRG_ZLIB, GRG_LVL_BEST,
				       GRG_SEC_NORMAL);
}

void
grg_context_free (GRG_CTX gctx)
{
#ifdef HAVE__DEV_RANDOM
	close (gctx->rnd);
#endif

	free (gctx);
}

grg_crypt_algo
grg_ctx_get_crypt_algo (const GRG_CTX gctx)
{
	return gctx->crypt_algo;
}

grg_hash_algo
grg_ctx_get_hash_algo (const GRG_CTX gctx)
{
	return gctx->hash_algo;
}

grg_comp_algo
grg_ctx_get_comp_algo (const GRG_CTX gctx)
{
	return gctx->comp_algo;
}

grg_comp_ratio
grg_ctx_get_comp_ratio (const GRG_CTX gctx)
{
	return gctx->comp_lvl;
}

grg_security_lvl
grg_ctx_get_security_lvl (const GRG_CTX gctx)
{
	return gctx->sec_lvl;
}

void
grg_ctx_set_crypt_algo (GRG_CTX gctx, const grg_crypt_algo crypt_algo)
{
	if (!gctx)
		return;

	gctx->crypt_algo = crypt_algo;
}

void
grg_ctx_set_hash_algo (GRG_CTX gctx, const grg_hash_algo hash_algo)
{
	if (!gctx)
		return;

	gctx->hash_algo = hash_algo;
}

void
grg_ctx_set_comp_algo (GRG_CTX gctx, const grg_comp_algo comp_algo)
{
	if (!gctx)
		return;

	gctx->comp_algo = comp_algo;
}

void
grg_ctx_set_comp_ratio (GRG_CTX gctx, const grg_comp_ratio comp_ratio)
{
	if (!gctx)
		return;

	gctx->comp_lvl = comp_ratio;
}

void
grg_ctx_set_security_lvl (GRG_CTX gctx, const grg_security_lvl sec_level)
{
	if (!gctx)
		return;

	gctx->sec_lvl = sec_level;
	reinit_random (gctx);
}

GRG_KEY
grg_key_gen (const unsigned char *pwd, const int pwd_len)
{
	GRG_KEY key;
	int real_pwd_len;

	if (!pwd)
		return NULL;

	if (pwd_len < 0)
		real_pwd_len = strlen (pwd);
	else
		real_pwd_len = pwd_len;

	key = (GRG_KEY) malloc (sizeof (struct _grg_key));

	if (!key)
		return NULL;

	mhash_keygen (KEYGEN_S2K_SIMPLE, MHASH_RIPEMD160, 0,
		      key->key_192_ripe, 24, NULL, 0, (unsigned char *) pwd,
		      real_pwd_len);
	mhash_keygen (KEYGEN_S2K_SIMPLE, MHASH_RIPEMD160, 0,
		      key->key_256_ripe, 32, NULL, 0, (unsigned char *) pwd,
		      real_pwd_len);
	mhash_keygen (KEYGEN_S2K_SIMPLE, MHASH_SHA1, 0, key->key_192_sha, 24,
		      NULL, 0, (unsigned char *) pwd, real_pwd_len);
	mhash_keygen (KEYGEN_S2K_SIMPLE, MHASH_SHA1, 0, key->key_256_sha, 32,
		      NULL, 0, (unsigned char *) pwd, real_pwd_len);

	return key;
}

GRG_KEY
grg_key_clone (const GRG_KEY src)
{
	GRG_KEY clone = (GRG_KEY) malloc (sizeof (struct _grg_key));
	
	if (clone)
		memcpy (clone, src, sizeof (struct _grg_key));

	return clone;
}

int
grg_key_compare (const GRG_KEY k1, const GRG_KEY k2)
{
	if (!k1 || !k2)
		return 0;

	if (memcmp (k1->key_256_ripe, k2->key_256_ripe, 32))
		return 0;

	return 1;
}

void
grg_key_free (const GRG_CTX gctx, GRG_KEY key)
{
	grg_free (gctx, key, sizeof (struct _grg_key));
}
