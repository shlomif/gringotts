/*  libGringotts - generic data encoding (crypto+compression) library
 *  (c) 2002, Germano Rizzo <mano@pluto.linux.it>
 *
 *  libgrg_tmp.c - functions to produce encrypted temp files
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

#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "libgrg_structs.h"
#include "libgrg_crypt.h"
#include "libgrg_utils.h"
#include "libgringotts.h"

#define	WRITEABLE	1
#define READABLE	0

GRG_TMPFILE
grg_tmpfile_gen (const GRG_CTX gctx)
{
	GRG_TMPFILE tf;
	char tmpname[] = "/tmp/___-XXXXXX";
	grg_crypt_algo ca;

	if (!gctx)
		return NULL;

	tf = (GRG_TMPFILE) malloc (sizeof (struct _grg_tmpfile));
	if (!tf)
		return NULL;

	ca = grg_ctx_get_crypt_algo (gctx);

	memcpy (tmpname + 5, gctx->header, HEADER_LEN);
	tf->tmpfd = mkstemp (tmpname);
	unlink (tmpname);
	memcpy (tmpname, "/tmp/___-XXXXXX", 15);

	if (tf->tmpfd < 0)
	{
		free (tf);
		return NULL;
	}

	tf->crypt =
		mcrypt_module_open (grg2mcrypt (ca), NULL, MCRYPT_CFB, NULL);
	if (tf->crypt == MCRYPT_FAILED)
	{
		close (tf->tmpfd);
		free (tf);
		return NULL;
	}

	tf->dKey = grg_get_key_size_static (ca);
	tf->key = grg_rnd_seq (gctx, tf->dKey);
	if(!tf->key)
	{
		close (tf->tmpfd);
		free (tf);
		return NULL;
	}

	tf->dIV = grg_get_block_size_static (ca);
	tf->IV = grg_rnd_seq (gctx, tf->dIV);
	if(!tf->IV)
	{
		close (tf->tmpfd);
		free (tf);
		return NULL;
	}

	tf->rwmode = WRITEABLE;

	return tf;
}

int
grg_tmpfile_write (const GRG_CTX gctx, GRG_TMPFILE tf,
		   const unsigned char *data, const long data_len)
{
	long dim;
	unsigned char *tocrypt;

	if (!gctx || !tf || !data)
		return GRG_ARGUMENT_ERR;

	if (tf->rwmode == READABLE)
		return GRG_TMP_NOT_WRITEABLE;

	if (mcrypt_generic_init (tf->crypt, tf->key, tf->dKey, tf->IV) < 0)
		return GRG_WRITE_ENC_INIT_ERR;

	dim = (data_len < 0) ? strlen (data) : data_len;

	tocrypt = grg_memconcat (2, gctx->header, HEADER_LEN, data, dim);
	if (!tocrypt)
		return GRG_MEM_ALLOCATION_ERR;

	if (mcrypt_generic (tf->crypt, tocrypt, dim + HEADER_LEN))
	{
		mcrypt_generic_deinit (tf->crypt);
		grg_free (gctx, tocrypt, dim + HEADER_LEN);
		return GRG_WRITE_ENC_INIT_ERR;
	}

	write (tf->tmpfd, &dim, sizeof (long));	//without considering endianity, since we
	write (tf->tmpfd, tocrypt, dim + HEADER_LEN);	//read and write on the same system.

	mcrypt_generic_deinit (tf->crypt);
	grg_free (gctx, tocrypt, dim + HEADER_LEN);

	fsync (tf->tmpfd);

	tf->rwmode = READABLE;
	return GRG_OK;
}

int
grg_tmpfile_read (const GRG_CTX gctx, const GRG_TMPFILE tf,
		  unsigned char **data, long *data_len)
{
	long dim;
	unsigned char *enc_data;

	if (!gctx || !tf)
		return GRG_ARGUMENT_ERR;

	if (tf->rwmode != READABLE)
		return GRG_TMP_NOT_YET_WRITTEN;

	if (mcrypt_generic_init (tf->crypt, tf->key, tf->dKey, tf->IV) < 0)
		return GRG_READ_ENC_INIT_ERR;

	lseek (tf->tmpfd, 0, SEEK_SET);

	read (tf->tmpfd, &dim, sizeof (long));

	enc_data = (unsigned char *) malloc (dim + HEADER_LEN);
	if (!enc_data)
		return GRG_MEM_ALLOCATION_ERR;
	
	read (tf->tmpfd, enc_data, dim + HEADER_LEN);

	if (mdecrypt_generic (tf->crypt, enc_data, dim + HEADER_LEN))
	{
		grg_unsafe_free (enc_data);
		return GRG_READ_ENC_INIT_ERR;
	}

	if (memcmp (enc_data, gctx->header, HEADER_LEN) != 0)
	{
		grg_unsafe_free (enc_data);
		return GRG_READ_PWD_ERR;
	}

	*data = grg_memdup (enc_data + HEADER_LEN, dim);
	if (!data)
	{
		grg_unsafe_free (enc_data);
		return GRG_MEM_ALLOCATION_ERR;
	}
	
	if (data_len)
		*data_len = dim;

	grg_unsafe_free (enc_data);

	return GRG_OK;
}

void
grg_tmpfile_close (const GRG_CTX gctx, GRG_TMPFILE tf)
{
	if (!tf)
		return;

	close (tf->tmpfd);
	mcrypt_module_close (tf->crypt);
	grg_free (gctx, tf->key, tf->dKey);
	grg_unsafe_free (tf->IV);
	grg_unsafe_free (tf);
	tf = NULL;
}
