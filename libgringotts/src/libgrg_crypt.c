/*  libGringotts - generic data encoding (crypto+compression) library
 *  (c) 2002, Germano Rizzo <mano@pluto.linux.it>
 *
 *  libgrg_crypt.c - routines for data encryption and writing
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
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "libgrg_crypt.h"
#include "libgrg_utils.h"
#include "libgrg_structs.h"
#include "libgringotts.h"

#include <mhash.h>
#include <zlib.h>
#include <bzlib.h>

unsigned int
grg_get_key_size_static (const grg_crypt_algo crypt_algo)
{
	if (crypt_algo == GRG_3DES)
		return 24;
	else
		return 32;
}

unsigned int
grg_get_key_size (const GRG_CTX gctx)
{
	return grg_get_key_size_static (gctx->crypt_algo);
}

unsigned int
grg_get_block_size_static (const grg_crypt_algo crypt_algo)
{
	switch (crypt_algo)
	{
	case GRG_3DES:
		return 8;
	case GRG_RIJNDAEL_256:
		return 32;
	default:
		return 16;
	}
}

unsigned int
grg_get_block_size (const GRG_CTX gctx)
{
	return grg_get_block_size_static (gctx->crypt_algo);
}

/**
 * get_CRC32:
 * @string: a byte sequence
 * @strlen: the length of the string
 *
 * Computes the CRC32 checksum of a byte sequence.
 *
 * Returns: the checksum
 */
static unsigned char *
get_CRC32 (const unsigned char *string, const long strlen)
{
	MHASH td;
	unsigned char *ret;

	td = mhash_init (MHASH_CRC32);

	if (td == MHASH_FAILED)
		exit (1);

	mhash (td, string, strlen);

	ret = mhash_end (td);

	return ret;
}

/**
 * compare_CRC32:
 * @CRC: the CRC to compare to
 * @toCheck: the byte sequence to compare the CRC to
 * @len: the byte sequence length
 *
 * Tells if a byte sequence has the provided CRC32, in other words if
 * it's equal to the previously CRC'ed one.
 *
 * Returns: TRUE or FALSE
 */
static int
compare_CRC32 (const unsigned char *CRC, const unsigned char *toCheck,
	       const long len)
{
	unsigned char *CRC2;
	int ret;

	if (!CRC || !toCheck)
		return 0;

	if (!len)
		return 1;

	CRC2 = get_CRC32 (toCheck, len);

	ret = !memcmp (CRC, CRC2, LIBGRG_CRC_LEN);

	free (CRC2);

	return ret;
}

unsigned char *
grg2mcrypt (const grg_crypt_algo algo)
{
	switch (algo)
	{
	case GRG_RIJNDAEL_128:
		return MCRYPT_RIJNDAEL_128;

	case GRG_SERPENT:
		return MCRYPT_SERPENT;

	case GRG_TWOFISH:
		return MCRYPT_TWOFISH;

	case GRG_CAST_256:
		return MCRYPT_CAST_256;

	case GRG_SAFERPLUS:
		return MCRYPT_SAFERPLUS;

	case GRG_LOKI97:
		return MCRYPT_LOKI97;

	case GRG_3DES:
		return MCRYPT_3DES;

	case GRG_RIJNDAEL_256:
		return MCRYPT_RIJNDAEL_256;

	default:
		return MCRYPT_SERPENT;
	}
}

static int
validate_mem (const GRG_CTX gctx, const void *mem, const long memDim)
{
	unsigned char vers;
	char *tmp;
	long rem;

	if (!gctx || !mem)
		return GRG_ARGUMENT_ERR;

	tmp = (char *) mem;
	rem = (memDim >= 0) ? memDim : strlen (mem);

	//checks the ID header
	if (memcmp (gctx->header, mem, HEADER_LEN))
		return GRG_READ_MAGIC_ERR;

	tmp += HEADER_LEN;
	rem -= HEADER_LEN;

	//checks the GRG_VERSION
	vers = tmp[0] - '0';	//makes the version as an ordinal, not a char anymore
	tmp++;
	rem--;

	if (vers != 3)		//add here all the supported versions
		return GRG_READ_UNSUPPORTED_VERSION;

	//checks the 1st CRC
	if (!compare_CRC32 (tmp, tmp + LIBGRG_CRC_LEN, rem - LIBGRG_CRC_LEN))
		return GRG_READ_CRC_ERR;

	return vers;
}

static void
update_gctx_from_mem (GRG_CTX gctx, const char algo)
{
	gctx->crypt_algo = (unsigned char) (algo & GRG_ENCRYPT_MASK);
	gctx->hash_algo = (unsigned char) (algo & GRG_HASH_MASK);
	gctx->comp_algo = (unsigned char) (algo & GRG_COMP_TYPE_MASK);
	gctx->comp_lvl = (unsigned char) (algo & GRG_COMP_LVL_MASK);
}

static unsigned char *
select_key (const GRG_CTX gctx, const GRG_KEY keystruct, int *dim)
{
	unsigned char *key;

	if (gctx->crypt_algo == GRG_3DES)
		*dim = 24;
	else
		*dim = 32;

	if (gctx->hash_algo == GRG_SHA1)
		key = grg_memdup (((*dim ==
				     24) ? keystruct->
				    key_192_sha : keystruct->key_256_sha),
				   *dim);
	else
		key = grg_memdup (((*dim ==
				     24) ? keystruct->
				    key_192_ripe : keystruct->key_256_ripe),
				   *dim);
	
	return key;
}

static int
decrypt_mem (const GRG_CTX gctx, const GRG_KEY keystruct, const void *mem,
	     long memDim, unsigned char **origData, long *origDim)
{
	unsigned char *IV, *ecdata, *curdata, *dimdata, *key, *CRC32b;
	int dIV, len, curlen, keylen, err;
	char *tmp;
	long oDim;
	MCRYPT mod;

	len = memDim - LIBGRG_DATA_POS;
	tmp = ((char *) mem) + LIBGRG_DATA_POS;
	
	dIV = grg_get_block_size_static (gctx->crypt_algo);
	IV = grg_memdup (tmp, dIV);
	if (!IV){
		return GRG_MEM_ALLOCATION_ERR;
	}

	tmp += dIV;
	len -= dIV;

	ecdata = grg_memdup (tmp, len);
	if (!ecdata)
	{
		grg_unsafe_free (IV);
		return GRG_MEM_ALLOCATION_ERR;
	}
	
	curdata = ecdata;
	curlen = len;

	//decrypts the encrypted data
	mod = mcrypt_module_open (grg2mcrypt (gctx->crypt_algo), NULL,
				  MCRYPT_CFB, NULL);

	if (mod == MCRYPT_FAILED)
	{
		grg_unsafe_free (ecdata);
		grg_unsafe_free (IV);
		return GRG_READ_ENC_INIT_ERR;
	}

	key = select_key (gctx, keystruct, &keylen);
	if (!key)
	{
		grg_unsafe_free (ecdata);
		grg_unsafe_free (IV);
		return GRG_MEM_ALLOCATION_ERR;
	}

	grg_XOR_mem (key, keylen, IV, dIV);

	mcrypt_generic_init (mod, key, keylen, IV);
	grg_free (gctx, key, keylen);
	key = NULL;
	grg_unsafe_free (IV);
		
	mdecrypt_generic (mod, ecdata, len);

	mcrypt_generic_deinit (mod);
	mcrypt_module_close (mod);

	//checks the 2nd CRC32

	CRC32b = grg_memdup (ecdata, LIBGRG_CRC_LEN);
	if (!CRC32b)
	{
		grg_unsafe_free (ecdata);
		return GRG_MEM_ALLOCATION_ERR;
	}

	curdata += LIBGRG_CRC_LEN;
	curlen -= LIBGRG_CRC_LEN;

	if (!compare_CRC32 (CRC32b, curdata, curlen))
	{
		grg_unsafe_free (ecdata);
		grg_unsafe_free (CRC32b);
		return GRG_READ_PWD_ERR;
	}

	grg_unsafe_free (CRC32b);
		
	//reads the uncompressed data length

	dimdata = grg_memdup (curdata, LIBGRG_DATA_DIM_LEN);
	if (!dimdata)
	{
		grg_unsafe_free (ecdata);
		return GRG_MEM_ALLOCATION_ERR;
	}

	curdata += LIBGRG_DATA_DIM_LEN;
	curlen -= LIBGRG_DATA_DIM_LEN;

	oDim = grg_char2long (dimdata);

	grg_free (gctx, dimdata, LIBGRG_DATA_DIM_LEN);
	dimdata = NULL;

	//uncompress the final data
	if (gctx->comp_lvl)
	{
		unsigned char *tmpData = (unsigned char *) malloc (oDim);

		if (!tmpData)
		{
			grg_unsafe_free (ecdata);
			return GRG_MEM_ALLOCATION_ERR;
		}
		
		if (gctx->comp_algo)	//bz2
			err = BZ2_bzBuffToBuffDecompress ((unsigned char *)
							  tmpData, (unsigned int *) &oDim,
							  (unsigned char *) curdata, curlen,
							  USE_BZ2_SMALL_MEM, 0);
		else		//zlib
			err = uncompress (tmpData, &oDim, curdata, curlen);

		if (err < 0)
		{
			grg_free (gctx, tmpData, oDim);
			tmpData = NULL;
			grg_unsafe_free (ecdata);
			return GRG_READ_COMP_ERR;
		}

		*origData = grg_memconcat (2, tmpData, oDim, "", 1);

		grg_free (gctx, tmpData, oDim);
		tmpData = NULL;
	}
	else
		*origData = grg_memconcat (2, curdata, oDim, "", 1);

	grg_unsafe_free (ecdata);

	if (!*origData){
		return GRG_MEM_ALLOCATION_ERR;
	}

	if (origDim != NULL)
		*origDim = oDim;

	return GRG_OK;
}

int
grg_encrypt_mem (const GRG_CTX gctx, const GRG_KEY keystruct, void **mem,
		 long *memDim, const unsigned char *origData,
		 const long origDim)
{
	unsigned char *compData, *chunk, *toCRC1, *CRC1, *toEnc, *key, *IV,
		*toCRC2, *CRC2, algo;
	unsigned int dIV, dKey, err;
	long compDim, uncDim;
	MCRYPT mod;

	if (!gctx || !keystruct || !origData)
			return GRG_ARGUMENT_ERR;

	uncDim = (origDim < 0) ? strlen (origData) : origDim;

	if (gctx->comp_lvl)
	{
		if (gctx->comp_algo)	//bz2
			compDim = (long) ((((float) uncDim) * 1.01) + 600);
		else		//libz
			compDim = (long) ((((float) uncDim) + 12) * 1.01);

		compData = (char *) malloc (compDim);
		if (!compData)
			return GRG_MEM_ALLOCATION_ERR;

		//compress the data
		if (gctx->comp_algo)	//bz2
			err = BZ2_bzBuffToBuffCompress (compData,
							(unsigned int *)
							&compDim,
							(unsigned char *)
							origData, uncDim,
							gctx->comp_lvl * 3, 0,
							0);
		else
			err = compress2 (compData, &compDim, origData, uncDim,
					 gctx->comp_lvl * 3);

		if (err < 0)
		{
			grg_free (gctx, compData, compDim);
			compData = NULL;
			compDim = 0;
			return GRG_WRITE_COMP_ERR;
		}
	}
	else
	{
		compDim = uncDim;
		compData = grg_memdup (origData, uncDim);
		if (!compData)
			return GRG_MEM_ALLOCATION_ERR;
	}

	chunk = grg_long2char (uncDim);

	//adds the CRC32 and DATA_LEN field
	toCRC1 = grg_memconcat (2, chunk, LIBGRG_DATA_DIM_LEN, compData,
				compDim);

	grg_free (gctx, chunk, LIBGRG_DATA_DIM_LEN);
	chunk = NULL;
	grg_free (gctx, compData, compDim);
	compData = NULL;
	
	if (!toCRC1)
		return GRG_MEM_ALLOCATION_ERR;

	compDim += LIBGRG_DATA_DIM_LEN;

	CRC1 = get_CRC32 (toCRC1, compDim);

	toEnc = grg_memconcat (2, CRC1, LIBGRG_CRC_LEN, toCRC1, compDim);

	grg_free (gctx, CRC1, LIBGRG_CRC_LEN);
	CRC1 = NULL;
	grg_free (gctx, toCRC1, compDim);
	toCRC1 = NULL;
	
	if (!toEnc)
		return GRG_MEM_ALLOCATION_ERR;

	compDim += LIBGRG_CRC_LEN;

	//encrypts the data
	mod = mcrypt_module_open (grg2mcrypt (gctx->crypt_algo), NULL,
				  MCRYPT_CFB, NULL);

	if (mod == MCRYPT_FAILED)
	{
		grg_free (gctx, toEnc, compDim);
		toEnc = NULL;
		return GRG_WRITE_ENC_INIT_ERR;
	}

	dIV = mcrypt_enc_get_iv_size (mod);
	IV = grg_rnd_seq (gctx, dIV);
	if (!IV)
	{
		grg_free (gctx, toEnc, compDim);
		toEnc = NULL;
		return GRG_MEM_ALLOCATION_ERR;
	}

	key = select_key (gctx, keystruct, &dKey);
	if (!key)
	{
		grg_unsafe_free (IV);
		grg_free (gctx, toEnc, compDim);
		toEnc = NULL;
		return GRG_MEM_ALLOCATION_ERR;
	}
	
	grg_XOR_mem (key, dKey, IV, dIV);

	err = mcrypt_generic_init (mod, key, dKey, IV);

	grg_free (gctx, key, dKey);
	key = NULL;

	if (err < 0)
	{
		grg_unsafe_free (IV);
		grg_free (gctx, toEnc, compDim);
		toEnc = NULL;
		return GRG_WRITE_ENC_INIT_ERR;
	}

	mcrypt_generic (mod, toEnc, compDim);

	mcrypt_generic_deinit (mod);
	mcrypt_module_close (mod);

	//adds algorithm and salt 

	algo = (unsigned char) (gctx->crypt_algo | gctx->hash_algo | gctx->
				comp_algo | gctx->comp_lvl);

	toCRC2 = grg_memconcat (3, &algo, LIBGRG_ALGO_LEN, IV, dIV, toEnc,
				compDim);

	grg_unsafe_free (IV);
	grg_free (gctx, toEnc, compDim);
	toEnc = NULL;

	if (!toCRC2)
		return GRG_MEM_ALLOCATION_ERR;

	compDim += LIBGRG_ALGO_LEN + dIV;

	//calculates the CRC32

	CRC2 = get_CRC32 (toCRC2, compDim);

	//writes it all

	*memDim = LIBGRG_ALGO_POS + compDim;
	*mem = malloc (*memDim);
	if (!*mem){
		grg_free (gctx, CRC2, LIBGRG_CRC_LEN);
		CRC2 = NULL;
		grg_free (gctx, toCRC2, compDim);
		toCRC2 = NULL;
		return GRG_MEM_ALLOCATION_ERR;
	}

	memcpy (((char *) *mem), gctx->header, HEADER_LEN);
	((char *) *mem)[HEADER_LEN] = LIBGRG_FILE_VERSION + '0';
	memcpy (((char *) *mem) + HEADER_LEN + LIBGRG_FILE_VERSION_LEN, CRC2,
		LIBGRG_CRC_LEN);
	grg_free (gctx, CRC2, LIBGRG_CRC_LEN);
	CRC2 = NULL;
	memcpy (((char *) *mem) + LIBGRG_ALGO_POS, toCRC2, compDim);
	grg_free (gctx, toCRC2, compDim);
	toCRC2 = NULL;

	return GRG_OK;
}

int
grg_validate_file_direct (const GRG_CTX gctx, const int fd)
{
	int ret, len;
	void *mem;

	if (fd < 0)
		return GRG_READ_FILE_ERR;

	if (!gctx)
		return GRG_ARGUMENT_ERR;

	len = lseek (fd, 0, SEEK_END);
	mem = mmap (NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);

	if (mem == MAP_FAILED)
		return GRG_READ_MMAP_ERR;

	ret = validate_mem (gctx, mem, len);

	munmap (mem, len);

	if (ret > 0)
		return GRG_OK;
	return ret;
}

int
grg_validate_file (const GRG_CTX gctx, const unsigned char *path)
{
	int fd, res;

	if (!gctx || !path)
		return GRG_ARGUMENT_ERR;

	fd = open (path, O_RDONLY);
	res = grg_validate_file_direct (gctx, fd);
	close (fd);

	return res;
}

int
grg_update_gctx_from_file_direct (GRG_CTX gctx, const int fd)
{
	int ret, len;
	void *mem;

	if (fd < 0)
		return GRG_READ_FILE_ERR;

	if (!gctx)
		return GRG_ARGUMENT_ERR;

	len = lseek (fd, 0, SEEK_END);
	mem = mmap (NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);

	if (mem == MAP_FAILED)
		return GRG_READ_MMAP_ERR;

	ret = validate_mem (gctx, mem, len);

	if (ret < 0)
	{
		munmap (mem, len);
		return ret;
	}

	update_gctx_from_mem (gctx, ((char *) mem)[LIBGRG_ALGO_POS]);

	munmap (mem, len);

	return GRG_OK;
}

int
grg_update_gctx_from_file (GRG_CTX gctx, const unsigned char *path)
{
	int fd, res;

	if (!gctx || !path)
		return GRG_ARGUMENT_ERR;

	fd = open (path, O_RDONLY);
	res = grg_update_gctx_from_file_direct (gctx, fd);
	close (fd);

	return res;
}

int
grg_decrypt_file_direct (const GRG_CTX gctx, const GRG_KEY keystruct,
			 const int fd, unsigned char **origData, long *origDim)
{
	int ret, len;
	void *mem;

	if (fd < 0)
		return GRG_READ_FILE_ERR;

	if (!gctx || !keystruct)
		return GRG_ARGUMENT_ERR;

	len = lseek (fd, 0, SEEK_END);
	mem = mmap (NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);

	if (mem == MAP_FAILED)
		return GRG_READ_MMAP_ERR;

	ret = validate_mem (gctx, mem, len);

	if (ret < 0)
	{
		munmap (mem, len);
		return ret;
	}

	update_gctx_from_mem (gctx, ((char *) mem)[LIBGRG_ALGO_POS]);

	ret = decrypt_mem (gctx, keystruct, mem, len, origData, origDim);

	munmap (mem, len);

	return ret;
}

int
grg_decrypt_file (const GRG_CTX gctx, const GRG_KEY keystruct,
		  const unsigned char *path, unsigned char **origData,
		  long *origDim)
{
	int fd, res;

	if (!gctx || !keystruct || !path)
		return GRG_ARGUMENT_ERR;

	fd = open (path, O_RDONLY);
	res = grg_decrypt_file_direct (gctx, keystruct, fd, origData,
				       origDim);
	close (fd);

	return res;
}

int
grg_encrypt_file_direct (const GRG_CTX gctx, const GRG_KEY keystruct,
			 const int fd, const unsigned char *origData,
			 const long origDim)
{
	int ret;
	void *mem;
	long memDim;

	if (!gctx || !keystruct || !origData)
		return GRG_ARGUMENT_ERR;

	ret = grg_encrypt_mem (gctx, keystruct, &mem, &memDim, origData,
			       origDim);

	if (ret < 0)
		return ret;

	if (fd < 3)
	{
		grg_unsafe_free (mem);
		return GRG_WRITE_FILE_ERR;
	}

	write (fd, mem, memDim);

	fsync (fd);

	//closing
	grg_unsafe_free (mem);

	return GRG_OK;
}

int
grg_encrypt_file (const GRG_CTX gctx, const GRG_KEY keystruct,
		  const unsigned char *path, const unsigned char *origData,
		  const long origDim)
{
	int fd, res;

	if (!gctx || !keystruct || !path || !origData)
		return GRG_ARGUMENT_ERR;

	fd = open (path, O_WRONLY | O_CREAT | O_TRUNC,
		   S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR);

	res = grg_encrypt_file_direct (gctx, keystruct, fd, origData,
				       origDim);
	close (fd);
	
	if (res < 0)
		unlink (path);

	return res;
}


int
grg_validate_mem (const GRG_CTX gctx, const void *mem, const long memDim)
{
	int ret;

	if (!mem || !gctx)
			return GRG_ARGUMENT_ERR;

	ret = validate_mem (gctx, mem, memDim);

	if (ret > 0)
		return GRG_OK;

	return ret;
}

int
grg_update_gctx_from_mem (GRG_CTX gctx, const void *mem, const long memDim)
{
	int ret = validate_mem (gctx, mem, memDim);
	if (ret < 0)
		return ret;

	update_gctx_from_mem (gctx, ((char *) mem)[LIBGRG_ALGO_POS]);

	return GRG_OK;
}

int
grg_decrypt_mem (const GRG_CTX gctx, const GRG_KEY keystruct, const void *mem,
		 const long memDim, unsigned char **origData, long *origDim)
{
	int ret;
	
	if (!mem || !gctx || !keystruct)
			return GRG_ARGUMENT_ERR;
	
	ret = validate_mem (gctx, mem, memDim);

	if (ret < 0)
		return ret;

	update_gctx_from_mem (gctx, ((char *) mem)[LIBGRG_ALGO_POS]);

	ret = decrypt_mem (gctx, keystruct, mem, memDim, origData, origDim);

	return ret;
}
