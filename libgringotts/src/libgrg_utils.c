/*  libGringotts - generic data encoding (crypto+compression) library
 *  (c) 2002, Germano Rizzo <mano@pluto.linux.it>
 *
 *  libgrg_utils.c - utility functions for libgringotts
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

#include "config.h"
#include "libgringotts.h"
#include "libgrg_crypt.h"
#include "libgrg_structs.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>

#include <mhash.h>

// Basically, the following 2 functions are the adaptation of string.h
// functions for byte sequences. Strings are byte sequence that are
// \0-terminated; in this case, this is dangerous, because a \0 can
// occour _inside_ the very sequence. Of course, there's no way to tell
// how long the sequence is, other than "remembering" it, and passing it
// to the functions.

/**
 * grg_memdup
 * @src: the source
 * @len: its length
 *
 * Duplicates a byte sequence into a new one
 *
 * Returns: a newly allocated (to free() afterwards) byte sequence
 */
unsigned char *
grg_memdup (const unsigned char *src, long len)
{
	unsigned char *ret;

	if (!src || !len)
		return NULL;

	ret = (unsigned char *) malloc (len);
	
	if (ret)
		memcpy (ret, src, len);

	return ret;
}

/**
 * grg_memconcat:
 * @count: the number of byte sequences to concatenate
 * @src1: the first byte sequence to concatenate
 * @len1: the length of the first sequence
 * @...: the other sequences/lengths
 *
 * Concatenates some byte sequences
 *
 * Returns: a newly allocated (to free() afterwards) byte sequence
 */
unsigned char *
grg_memconcat (const int count, ...)
{
	va_list ap;
	unsigned char *ret, *tmp, *strings[count];
	int dim[count], i, dimtot = 0;

	if (count < 1)
		return NULL;

	va_start (ap, count);

	for (i = 0; i < count; i++)
	{
		strings[i] = va_arg (ap, unsigned char *);
		dim[i] = va_arg (ap, int);
		dimtot += dim[i];
	}

	if (!dimtot)
		return NULL;

	ret = (unsigned char *) malloc (dimtot);
	if (!ret)
		return NULL;

	tmp = ret;
	for (i = 0; i < count; i++)
	{
		memcpy (tmp, strings[i], dim[i]);
		tmp += dim[i];
	}

	va_end (ap);

	return ret;
}

/**
 * grg_get_version:
 * Returns the version string
 *
 * Returns: a newly-allocated string, to be free()'d afterwards
 */
unsigned char *
grg_get_version (void)
{
	return (unsigned char *) strdup (LIBGRG_VERSION);
}

/**
 * grg_get_int_version:
 * Returns the version as a (comparable) integer
 *
 * Returns: a positional integer, of the form xxyyzz, for libgringotts version x.y.z
 */
unsigned int
grg_get_int_version (void)
{
	char *rem;
	unsigned int vers = strtol (LIBGRG_VERSION, &rem, 10) * 10000;
	vers += strtol (rem, &rem, 10) * 100;
	vers += strtol (rem, NULL, 10);

	return vers;
}

/**
 * grg_XOR_mem:
 * @src: the byte sequence to XOR
 * @src_len: its length
 * @mask: the byte sequence to XOR the first with. It will be repeated if shorter.
 * @mask_length: its length
 *
 * XORs a byte sequence with another, eventually repeating the latter to match the first.
 */
void
grg_XOR_mem (unsigned char *src, int src_len, unsigned char *mask,
	     int mask_len)
{
	int i;
	for (i = 0; i < src_len; i++)
		src[i] ^= mask[i % mask_len];
}

/**
 * grg_long2char:
 * @seed: the long to convert
 *
 * Converts a long into four bytes
 *
 * Returns: a newly allocated 4-bytes sequence, to free after use
 */
unsigned char *
grg_long2char (const long seed)
{
	unsigned char *ret;
	long tmp = seed;
	int i;

	ret = (unsigned char *) malloc (4);

	if (ret)
		for (i = 3; i >= 0; i--, tmp >>= 8)
			ret[i] = tmp & 0x0ff;

	return ret;
}

/**
 * grg_char2long:
 * @seed: the 4-char sequence to convert
 *
 * Reverts grg_long2char(), converting back into a long
 *
 * Returns: a long
 */
long
grg_char2long (const unsigned char *seed)
{
	long ret = 0;
	int i;

	for (i = 3; i >= 0; i--)
		ret |= seed[i] << ((3 - i) * 8);

	return ret;
}

void
grg_rnd_seq_direct (const GRG_CTX gctx, unsigned char *toOverwrite,
	const unsigned int size)
{
	int csize = size;

	if (!gctx || !size || !toOverwrite)
		return;

	if (csize < 0)
		csize = strlen (toOverwrite);
	
#ifdef HAVE__DEV_RANDOM
	read (gctx->rnd, toOverwrite, csize);
#else
	int step = sizeof (long int), i;
	long int val;

	for (i = 0; i < csize; i += step)
	{
		val = random ();
		memcpy (toOverwrite + i, &val, step);
	}

	for (i -= step; i < csize; i++)
		toOverwrite[i] = (random () / 256) % 256;
#endif
}

/**
 * grg_rnd_seq:
 * @size: the size of the sequence to generate
 *
 * Generates a random sequence of bytes.
 *
 * Returns: a newly-allocated byte sequence
 */
unsigned char *
grg_rnd_seq (const GRG_CTX gctx, const unsigned int size)
{
	unsigned char *ret;
	
	if (!gctx || size < 1)
		return NULL;

	ret = (unsigned char *) malloc (size);

	if (!ret)
		return NULL;

	grg_rnd_seq_direct (gctx, ret, size);

	return ret;
}

/**
 * grg_rnd_chr:
 *
 * Returns a random byte.
 *
 * Returns: a random byte.
 */
unsigned char
grg_rnd_chr (const GRG_CTX gctx)
{
	unsigned char rnd;
	if (!gctx)
		return 0;
#ifdef HAVE__DEV_RANDOM
	read (gctx->rnd, &rnd, 1);
#else
	rnd = (random () / 256) % 256;
#endif
	return rnd;
}

/**
 * grg_free:
 * @pntr: pointer to the memory to free
 * @dim: length of the sequence; if -1 it must be NULL-terminated
 *
 * Frees a sequence of bytes, overwriting it with random data
 */
void
grg_free (const GRG_CTX gctx, void *alloc_data, const long dim)
{
	char *pntr = (char *) alloc_data;

	if (!pntr)
		return;
	
	if (gctx)
		grg_rnd_seq_direct (gctx, pntr, (dim >= 0) ? dim : strlen (pntr));

	free (pntr);
}

/**
 * grg_unsafe_free:
 * @alloc_data: pointer to the memory to free
 *
 * Frees a memory segment; wrapper for free(), to behave correctly when NULL
 * is passed as argument
 */
void
grg_unsafe_free (void *alloc_data)
{
	if (!alloc_data)
		return;

	free (alloc_data);
}

/**
 * grg_ascii_pwd_quality:
 * @pwd: a non-multibyte string with the password
 * @pwd_len: the maximum length, to grant a termination. If
 * negative, the string _must_ be null-terminated
 *
 * Calculates an indicative value proportional to the password
 * "quality". Returns a value from 0 to 1, where 0 is the worst
 * password (4 char, all numeric), 1 the approximation of 256
 * bits of real data in the password, or better. The scale is 
 * logarythmic, so it will grow faster for shorter passwords than 
 * for larger ones, since improvements in a scarcely-secure password
 * are more valuable than improvements in better ones.<br>
 * Anyway, this should be used only for ASCII-like passwords, null
 * terminated. If you want to eval more "generic" sequences of 
 * bytes, use grg_file_pwd_quality. If you use multibyte encodings,
 * you must convert them to your locale encoding before evaluation.
 * 
 * Returns: a double between 0 and 1, inclusive
 */
double
grg_ascii_pwd_quality (const unsigned char *pwd, const long pwd_len)
{
	int A = FALSE, a = FALSE, n = FALSE, p = FALSE;
	long i = 0;
	long tmp = (pwd_len < 0) ? LONG_MAX - 1 : pwd_len;
	int basin = 0;
	double ret;

	if (!pwd)
		return 0.0;

	while ((i < tmp) && (pwd[i] != '\0'))
	{

		if (islower (pwd[i]))
		{
			a = TRUE;
			i++;
			continue;
		}

		if (isdigit (pwd[i]))
		{
			n = TRUE;
			i++;
			continue;
		}

		if (isupper (pwd[i]))
		{
			A = TRUE;
			i++;
			continue;
		}

		p = TRUE;
		i++;
	}

	if (i < 4)
		return 0.0;

	if (a)
		basin += 26;
	if (A)
		basin += 26;
	if (n)
		basin += 10;
	if (p)
		basin += 32;

#undef LOG2
#define LOG2(val) \
		(log(val)/0.693147)	/* log, basis 2 */
#define QVAL(length, num_char) \
		(length*LOG2(num_char))	/* number of `real' bits in pwd */
#define QMAX	5.545177	//log(256)
#define QMIN	2.586840	//log(4*LOG2(10))
#define QDIF	2.958337	//QMAX-QMIN

	ret = (log (QVAL (i, basin)) - QMIN) / QDIF;

#undef LOG2
#undef QVAL
#undef QMAX
#undef QMIN
#undef QDIF

	if (ret < 0)
		return 0.0;
	if (ret > 1)
		return 1.0;
	return ret;
}

/**
 * grg_file_pwd_quality:
 * @pwd_path: the path to the file to use as password
 *
 * Calculates an indicative value proportional to the password
 * "quality", in the case you want to use a file content as a
 * password. Returns a value from 0 to 1, where 0 is the worst
 * case (empty file), 1 the approximation of 256 bits of real 
 * data, or better. The scale is linear.
 * 
 * Returns: a double between 0 and 1, inclusive
 */
double
grg_file_pwd_quality (const unsigned char *pwd_path)
{
	double ret;
	int pdf;

	pdf = open (pwd_path, O_RDONLY);

	if (pdf < 3)
	{
		close (pdf);
		return 0.0;
	}

	ret = ((double) (lseek (pdf, 0, SEEK_END))) / 32.0;

	close (pdf);

	if (ret < 0)
		return 0.0;
	if (ret > 1)
		return 1.0;
	return ret;
}


#define CHAR64(c) \
	((c < 0 || c > 127) ? -1 : index_64[c])

static const char basis_64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char index_64[128] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};

unsigned char *
grg_encode64 (const unsigned char *in, const int inlen,
	      unsigned int *outlen)
{
	unsigned char *out, *ret;
	unsigned char oval;
	unsigned int olen, origlen;

	if (!in)
		return NULL;

	origlen = (inlen >= 0) ? inlen : strlen (in);
	olen = (origlen + 2) / 3 * 4 + 1;
	out = (unsigned char *) malloc (olen);
	if (!out)
		return NULL;

	ret = out;
	if (outlen)
		*outlen = olen;

	while (origlen >= 3)
	{
		*out++ = basis_64[in[0] >> 2];
		*out++ = basis_64[((in[0] << 4) & 0x30) | (in[1] >> 4)];
		*out++ = basis_64[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
		*out++ = basis_64[in[2] & 0x3f];
		in += 3;
		origlen -= 3;
	}
	if (origlen > 0)
	{
		*out++ = basis_64[in[0] >> 2];
		oval = (in[0] << 4) & 0x30;
		if (origlen > 1)
			oval |= in[1] >> 4;
		*out++ = basis_64[oval];
		*out++ = (origlen < 2) ? '=' : basis_64[(in[1] << 2) & 0x3c];
		*out++ = '=';
	}
	
	ret[olen - 1] = '\0';

	return ret;
}

unsigned char *
grg_decode64 (const unsigned char *in, const int inlen,
	      unsigned int *outlen)
{
	unsigned olen, lup, tmpinlen;
	int c1, c2, c3, c4;
	char *out, *ret;

	if (!in)
		return NULL;

	tmpinlen = (inlen >= 0) ? inlen : strlen (in); 

	olen = tmpinlen / 4 * 3;
	if (in[tmpinlen - 1] == '=')
	{
		olen--;
		if (in[tmpinlen - 2] == '=')
			olen--;
	}

	out = (char *) malloc (olen+1);
	if (!out)
		return NULL;

	ret = out;

	if (in[0] == '+' && in[1] == ' ')
		in += 2;

	if (*in == '\0')
		return NULL;

	for (lup = 0; lup < tmpinlen / 4; lup++)
	{
		c1 = in[0];
		if (CHAR64 (c1) == -1)
			return NULL;
		c2 = in[1];
		if (CHAR64 (c2) == -1)
			return NULL;
		c3 = in[2];
		if (c3 != '=' && CHAR64 (c3) == -1)
			return NULL;
		c4 = in[3];
		if (c4 != '=' && CHAR64 (c4) == -1)
			return NULL;
		in += 4;
		*out++ = (CHAR64 (c1) << 2) | (CHAR64 (c2) >> 4);
		if (c3 != '=')
		{
			*out++ = ((CHAR64 (c2) << 4) & 0xf0) | (CHAR64 (c3) >>
								2);
			if (c4 != '=')
				*out++ = ((CHAR64 (c3) << 6) & 0xc0) |
					CHAR64 (c4);
		}
	}

	if (outlen)
		*outlen = olen;

	ret[olen] = '\0';

	return ret;
}

int
grg_file_shred (const char *path, const int npasses)
{

#define SHRED_BLOCK_SIZE	65536

	int fd, dim, tmpnpasses, i/* , j */;
	struct stat buf;
	char *mem;
	GRG_CTX gctx;

	fd = open (path, O_RDWR);

	if (fd < 3)
	{
		close (fd);
		return GRG_SHRED_CANT_OPEN_FILE;
	}
	
	tmpnpasses = (npasses > 0) ? npasses : 1;

	fstat (fd, &buf);

	if (buf.st_nlink > 1)
	{
		close (fd);
		return GRG_SHRED_YET_LINKED;
	}

	dim = buf.st_size;

	mem = mmap (NULL, dim, PROT_WRITE, MAP_SHARED, fd, 0);

	if (mem == MAP_FAILED)
	{
		close (fd);
		return GRG_SHRED_CANT_MMAP;
	}

	gctx = grg_context_initialize_defaults ("GRG");
	if (!gctx)
	{
		close (fd);
		return GRG_MEM_ALLOCATION_ERR;
	}

	for (i = 0; i < tmpnpasses; i++)
	{
/*		int rem = dim % SHRED_BLOCK_SIZE;

		for (j = SHRED_BLOCK_SIZE; j < dim; j += SHRED_BLOCK_SIZE)
			grg_rnd_seq_direct (gctx, mem + j - SHRED_BLOCK_SIZE, SHRED_BLOCK_SIZE);
		grg_rnd_seq_direct (gctx, mem + dim - rem, rem);
*/
		grg_rnd_seq_direct (gctx, mem, dim);
		fsync (fd);
	}

	munmap (mem, dim);
	close (fd);
	unlink (path);
	grg_context_free (gctx);

	sync ();

	return 0;
}
