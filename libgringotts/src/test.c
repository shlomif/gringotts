/*  libGringotts - generic data encoding (crypto+compression) library
 *  (c) 2002, Germano Rizzo <mano@pluto.linux.it>
 *
 *  test.c - test suite for libGringotts
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

/**
 * TODO:
 * o The test suite shouldn't stop after the first error, but go on. The
 *   matter is, subsequent tests may fail with nasty segfaults.. add checks!
 * o Many entities don't get properly freed after use. Not too serious, but
 *   noteworthy
 * o Add compatibility tests, i.e. decrypting a "old" known-as-good file
 * o testA() fails sometimes. I wonder why.
 */ 

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "libgringotts.h"

#define BOH		2
#define KO		1
#define OK		0

#define TEST_DIM	10240	//10 Kb

typedef int (* TEST_FUNC)(void);

static int counter = 0;

static GRG_CTX gctx;
static GRG_KEY key;
static GRG_TMPFILE tmp;

static void doTest (char *desc, TEST_FUNC test)
{
	int res;
	printf("%d) %s... ", ++counter, desc);
	res = test();
	if (res == OK){
		printf ("Ok\n\n");
		return;
	}
	if (res == BOH){
		printf ("Not passed\a\n\n");
		return;
	}
	if (res == KO){
		printf ("Failed\a\n\n");
		exit(1);
	}
	printf ("Failed with error code %d\a\n\n", res);
	exit(1);
}

static int test1()
{//creation of a context
	gctx = grg_context_initialize ("TST", GRG_TWOFISH, GRG_RIPEMD_160, GRG_BZIP, GRG_LVL_GOOD, GRG_SEC_PARANOIA); 
	if (gctx)
		return OK;
	else
		return KO;
}

static int test2()
{//verifies that the values of the created context are consistent
	if (grg_get_key_size(gctx) != 32 || 
		grg_get_block_size(gctx) != 16 ||
		grg_ctx_get_crypt_algo(gctx) != GRG_TWOFISH ||
		grg_ctx_get_hash_algo(gctx) != GRG_RIPEMD_160 ||
		grg_ctx_get_comp_algo(gctx) != GRG_BZIP ||
		grg_ctx_get_comp_ratio(gctx) != GRG_LVL_GOOD ||
		grg_ctx_get_security_lvl(gctx) != GRG_SEC_PARANOIA)
		return BOH;
	return OK;
}

static int test3()
{//change of values, and check for consistency
	grg_ctx_set_crypt_algo(gctx, GRG_SERPENT);
	grg_ctx_set_hash_algo(gctx, GRG_SHA1);
	grg_ctx_set_comp_algo(gctx, GRG_ZLIB);
	grg_ctx_set_comp_ratio(gctx, GRG_LVL_BEST);
	grg_ctx_set_security_lvl(gctx, GRG_SEC_NORMAL);

	if (grg_get_key_size(gctx) != 32 || 
		grg_get_block_size(gctx) != 16 ||
		grg_ctx_get_crypt_algo(gctx) != GRG_SERPENT ||
		grg_ctx_get_hash_algo(gctx) != GRG_SHA1 ||
		grg_ctx_get_comp_algo(gctx) != GRG_ZLIB ||
		grg_ctx_get_comp_ratio(gctx) != GRG_LVL_BEST ||
		grg_ctx_get_security_lvl(gctx) != GRG_SEC_NORMAL)
		return BOH;
	return OK;
}

static int test4()
{//key generation
	key = grg_key_gen ("password", 8);
	if (key)
		return OK;
	else
		return KO;
}

static int test5()
{//key generation without giving a length, key cloning, key comparison
	int ret;
	GRG_KEY key2 = grg_key_gen ("password", -1);
	GRG_KEY key3 = grg_key_clone (key);

	if (grg_key_compare(key, key2) &&
		grg_key_compare(key2, key3) &&
		grg_key_compare(key3, key))
		ret = OK;
	else
		ret = KO;

	grg_key_free (gctx, key2);
	grg_key_free (gctx, key3);

	return ret;
}

static int test6()
{//base-64 coding and decoding of a very long binary string at random
	int ret, olen;
	unsigned char *orig, *based, *debased;

	olen = TEST_DIM;
	orig = grg_rnd_seq (gctx, TEST_DIM);

	based = grg_encode64 (orig, olen, NULL);
	debased = grg_decode64 (based, -1, &olen);
	
	if (strncmp (orig, debased, olen) == 0)
		ret = OK;
	else
		ret = KO;
	
	free (orig);
	free (based);
	free (debased);
	
	return ret;
}

static int test7()
{//random number generator functions
	char r1, r2, r3;
	char *rs1, *rs2;
	int ret;

	r1 = grg_rnd_chr (gctx);
	r2 = grg_rnd_chr (gctx);
	r3 = grg_rnd_chr (gctx);

	if (r1 == r2 && r2 == r3)
		return KO;

	rs1 = grg_rnd_seq (gctx, TEST_DIM);
	rs2 = grg_rnd_seq (gctx, TEST_DIM);

	if (memcmp (rs1, rs2, TEST_DIM) == 0) {
		free (rs1);
		free (rs2);
		return KO;
	}

	memcpy (rs1, rs2, TEST_DIM);
	grg_rnd_seq_direct (gctx, rs1, TEST_DIM);

	if (memcmp (rs1, rs2, TEST_DIM) == 0)
		ret = KO;
	else
		ret = OK;

	free (rs1);
	free (rs2);

	return ret;
}

static int test8()
{//free-ers [not properly tested]
	char *mem = (char *) malloc (TEST_DIM);

	grg_free (gctx, mem, TEST_DIM);
	mem = NULL;
	grg_free (gctx, mem, TEST_DIM);

	mem = strdup ("Hullo!!");

	grg_free (gctx, mem, -1);

	return OK;
}

static int test9()
{//file wiping utility [not properly tested]
	char name[]="/tmp/libgrg-tmp-XXXXXX";
	int fd = mkstemp (name);
	if (fd < 0)
		return KO;

	write (fd, "hullo", 5);
	close (fd);

	grg_file_shred (name, 32);

	fd = open (name, O_RDONLY);
	if (fd < 0)
		return OK;

	return KO;
}

static int testA()
{//password quality, string pwd
	#define PWD1 "aaaaab"
	#define PWD2 "qwerty"
	#define PWD3 "qWerty"
	#define PWD4 "q2w3e4"
	#define PWD5 "de3456"
	#define PWD6 "dE3456"
	#define PWD7 "q123456"
	#define PWD8 "23.23k2"
	// p1=p2 ; p4=p5 ; p4<p3 ; p2<p4<p6 ; p5<p7<p8<p9 ; 0 < [p*] < 1
	
	double p1 = grg_ascii_pwd_quality (PWD1, -1),
		p2 = grg_ascii_pwd_quality (PWD2, -1),
		p3 = grg_ascii_pwd_quality (PWD3, -1),
		p4 = grg_ascii_pwd_quality (PWD4, -1),
		p5 = grg_ascii_pwd_quality (PWD5, -1),
		p6 = grg_ascii_pwd_quality (PWD6, -1),
		p7 = grg_ascii_pwd_quality (PWD7, -1),
		p8 = grg_ascii_pwd_quality (PWD8, -1);
	char *PWD9 = grg_rnd_seq (gctx, 256);
	double p9 = grg_ascii_pwd_quality (PWD9, 256);

	free (PWD9);
	if (p1 != p2 ||
		p4 != p5 ||
		p4 >= p3 ||
		p2 >= p4 || p4 >= p6 ||
		p5 >= p7 || p7 >= p8 || p8 >= p9)
		return KO;

	if (p1 <= 0 || p1 >= 1 ||
		p2 <= 0 || p2 >= 1 ||
		p3 <= 0 || p3 >= 1 ||
		p4 <= 0 || p4 >= 1 ||
		p5 <= 0 || p5 >= 1 ||
		p6 <= 0 || p6 >= 1 ||
		p7 <= 0 || p7 >= 1 ||
		p8 <= 0 || p8 >= 1 ||
		p9 <= 0 || p9 > 1)
		return KO;

	return OK;
}

static int testB()
{//password quality, file pwd
	char name1[]="/tmp/libgrg-tmp1-XXXXXX";
	int fd1 = mkstemp (name1);
	double p1;
	char name2[]="/tmp/libgrg-tmp2-XXXXXX";
	int fd2 = mkstemp (name2);
	double p2;
	char name3[]="/tmp/libgrg-tmp3-XXXXXX";
	int fd3 = mkstemp (name3);
	double p3;

	write (fd1, "        ", 8); close (fd1);
	write (fd2, "                ", 16); close (fd2);
	write (fd3, "                                ", 32); close (fd3);

	p1 = grg_file_pwd_quality (name1); unlink (name1);
	p2 = grg_file_pwd_quality (name2); unlink (name2);
	p3 = grg_file_pwd_quality (name3); unlink (name3);
	
	if (p1 >= p2 || p2 >= p3 ||
		p1 <= 0 || p1 >= 1 ||
		p2 <= 0 || p2 >= 1 ||
		p3 <= 0 || p3 > 1)
		return KO;

	return OK;
}

static int testC()
{//GRG_TMP creation
	tmp = grg_tmpfile_gen (gctx);
	if (tmp)
		return OK;
	return KO;
}

static int testD()
{//Reading and writing of data on a temp file
	unsigned char *data = grg_rnd_seq (gctx, TEST_DIM), *stone;
	int ret;

	ret = grg_tmpfile_write (gctx, tmp, data, TEST_DIM);
	if (ret < 0)
		return ret;
	ret = grg_tmpfile_read (gctx, tmp, &stone, NULL);
	if (ret < 0)
		return ret;
	return OK;
}

static int testE()
{//data encoding and decoding in memory
	unsigned char *data = grg_rnd_seq (gctx, TEST_DIM), *data2;
	void *stone = NULL;
	int ret, rval, d;
	long fdim, ffdim;

	d=TEST_DIM;
	ret=grg_encrypt_mem(gctx, key, &stone, &fdim, data, TEST_DIM);
	if (ret < 0){
		free (data);
		if (stone)
			free (stone);
		return ret;
	}
	ret=grg_decrypt_mem(gctx, key, stone, fdim, &data2, &ffdim);
	if (ret < 0){
		free (data);
		free (stone);
		if (data2)
			free (data2);
		return ret;
	}
	if (ffdim != TEST_DIM || memcmp (data, data2, TEST_DIM) != 0)
		rval = KO;
	else
		rval = OK;
	free (data);
	free (stone);
	free (data2);
	return rval;
}

static int testF()
{//data validating in memory
	unsigned char *data = grg_rnd_seq (gctx, TEST_DIM);
	void *stone;
	int ret;
	long fdim;

	grg_encrypt_mem(gctx, key, &stone, &fdim, data, TEST_DIM);
	ret=grg_validate_mem (gctx, stone, fdim);
	if (ret < 0){
		free (data);
		free (stone);
		return ret;
	}
	free (data);
	free (stone);
	return OK;
}

static int testG()
{//data encoding and decoding in files (direct variant)
	unsigned char *data = grg_rnd_seq (gctx, TEST_DIM), *data2;
	char name[]="/tmp/libgrg-tmp-XXXXXX";
	int fd = mkstemp (name);
	int ret, rval;
	long ffdim;

	if (fd < 0)
		return KO;

	ret=grg_encrypt_file_direct(gctx, key, fd, data, TEST_DIM);
	if (ret < 0){
		free (data);
		return ret;
	}
	close (fd);
	
	fd = open (name, O_RDONLY);
	if (fd < 0)
		return KO;
	ret=grg_decrypt_file_direct(gctx, key, fd, &data2, &ffdim);
	if (ret < 0){
		free (data);
		if (data2)
			free (data2);
		return ret;
	}
	close (fd);
	unlink (name);
	if (ffdim != TEST_DIM || memcmp (data, data2, TEST_DIM) != 0)
		rval = KO;
	else
		rval = OK;
	free (data);
	free (data2);
	return rval;
}

static int testH()
{//data validating in files (direct variant)
	unsigned char *data = grg_rnd_seq (gctx, TEST_DIM);
	char name[]="/tmp/libgrg-tmp-XXXXXX";
	int fd = mkstemp (name);
	int ret;

	if (fd < 0)
		return KO;

	grg_encrypt_file_direct(gctx, key, fd, data, TEST_DIM);
	close (fd);

	fd = open (name, O_RDONLY);
	if (fd < 0)
		return KO;
	ret=grg_validate_file_direct (gctx, fd);
	close (fd);
	unlink (name);
	if (ret < 0){
		free (data);
		return ret;
	}
	free (data);
	return OK;
}


static int testI()
{//data encoding and decoding in files
	unsigned char *data = grg_rnd_seq (gctx, TEST_DIM), *data2;
	char name[]="/tmp/libgrg-tmp-XXXXXX";
	int ret, rval, fd;
	long ffdim;

	fd = mkstemp (name);
	close (fd);
	unlink (name);

	ret=grg_encrypt_file (gctx, key, name, data, TEST_DIM);
	if (ret < 0){
		free (data);
		return ret;
	}
	
	ret=grg_decrypt_file (gctx, key, name, &data2, &ffdim);
	if (ret < 0){
		free (data);
		if (data2)
			free (data2);
		return ret;
	}

	unlink (name);
	if (ffdim != TEST_DIM || memcmp (data, data2, TEST_DIM) != 0)
		rval = KO;
	else
		rval = OK;
	free (data);
	free (data2);
	return rval;
}

static int testL()
{//data validating in files
	unsigned char *data = grg_rnd_seq (gctx, TEST_DIM);
	char name[]="/tmp/libgrg-tmp-XXXXXX";
	int ret, fd;

	fd = mkstemp (name);
	close (fd);
	unlink (name);

	grg_encrypt_file (gctx, key, name, data, TEST_DIM);

	ret=grg_validate_file (gctx, name);
	unlink (name);
	if (ret < 0){
		free (data);
		return ret;
	}
	free (data);
	return OK;
}

#define TEST_STRING "TEST_STRING"
#define TEST_STRING_DIM 11
#define ENC_STRING "VFNUM/Q2e5UfEC+5qi4MGcgHx6MYh8BLY0OjeYVq6sN8db1Hg15ZmxOUu5JN1yg2R7XBYRLvI1/eSTXUQ4dbLub+yIc2QU5TQ2TskJJHrg=="

static int testM()
{//backwards compatibility
	int ret, rval;
	unsigned int fdim;
	long ffdim;
	unsigned char *data = grg_decode64(ENC_STRING, -1, &fdim), *data2;

	ret=grg_decrypt_mem(gctx, key, data, fdim, &data2, &ffdim);
	if (ret < 0){
		free (data);
		if (data2)
			free (data2);
		return ret;
	}

	if (ffdim != TEST_STRING_DIM || memcmp (TEST_STRING, data2, TEST_STRING_DIM) != 0)
		rval = KO;
	else
		rval = OK;

	free (data);
	free (data2);
	return rval;
}

int main ()
{
	char *version = grg_get_version();
	printf("\nlibGringotts %s starting tests...\n\n", version);
	free (version);

	printf("  -= GRG_CTX structure =-\n\n");
	doTest("Context creation", test1);
	doTest("Context init sets valid parameters", test2);
	doTest("Context changes parameters correctly", test3);
	printf("\n");

	printf("  -= Utility functions =-\n\n");
	doTest("Random number generators", test7);
	doTest("grg_free() function", test8);
	doTest("Base64 conversions", test6);
	doTest("File shredding", test9);
	doTest("Password quality test (strings)", testA);
	doTest("Password quality test (files)", testB);
	printf("\n");

	printf("  -= GRG_KEY structure =-\n\n");
	doTest("Key creation", test4);
	doTest("Key cloning and comparison", test5);
	printf("\n");

	printf("  -= Encryption/decryption =-\n\n");
	doTest("Data encryption and decryption in memory", testE);
	doTest("Data format validation in memory", testF);
	doTest("Data encryption and decryption in files (using file descriptor)", testG);
	doTest("Data format validation in files (using file descriptor)", testH);
	doTest("Data encryption and decryption in files (using filename)", testI);
	doTest("Data format validation in files (using filename)", testL);
	printf("\n");

	printf("  -= Enc/decryption details =-\n\n");
	grg_ctx_set_crypt_algo(gctx, GRG_AES);
	grg_ctx_set_hash_algo(gctx, GRG_RIPEMD_160);
	grg_ctx_set_comp_algo(gctx, GRG_ZLIB);
	grg_ctx_set_comp_ratio(gctx, GRG_LVL_BEST);
	doTest("AES (Rijndael 128) encryption", testE);
	grg_ctx_set_crypt_algo(gctx, GRG_SERPENT);
	doTest("Serpent encryption", testE);
	grg_ctx_set_crypt_algo(gctx, GRG_TWOFISH);
	doTest("Twofish encryption", testE);
	grg_ctx_set_crypt_algo(gctx, GRG_CAST_256);
	doTest("CAST-256 encryption", testE);
	grg_ctx_set_crypt_algo(gctx, GRG_SAFERPLUS);
	doTest("Safer+ encryption", testE);
	grg_ctx_set_crypt_algo(gctx, GRG_LOKI97);
	doTest("Loki97 encryption", testE);
	grg_ctx_set_crypt_algo(gctx, GRG_3DES);
	doTest("Triple-DES encryption", testE);
	grg_ctx_set_crypt_algo(gctx, GRG_RIJNDAEL_256);
	doTest("Rijndael 256 encryption", testE);
	printf("\n");
	grg_ctx_set_crypt_algo(gctx, GRG_SERPENT);
	grg_ctx_set_hash_algo(gctx, GRG_SHA1);
	doTest("SHA-1 hashing", testE);
	grg_ctx_set_hash_algo(gctx, GRG_RIPEMD_160);
	doTest("Ripemd 160 hashing", testE);
	printf("\n");
	grg_ctx_set_comp_algo(gctx, GRG_ZLIB);
	doTest("ZLib compression", testE);
	grg_ctx_set_comp_algo(gctx, GRG_BZIP);
	doTest("BZip2 compression", testE);
	grg_ctx_set_comp_ratio(gctx, GRG_LVL_NONE);
	doTest("No compression", testE);
	printf("\n");

	printf("  -= Encrypted Temp Files =-\n\n");
	doTest("Tmpfile creation", testC);
	doTest("Tmpfile reading and writing", testD);
	printf("\n");

	printf("  -= Other tests =-\n\n");
	doTest("Backwards compatibility", testM);
	printf("\n");

	printf("...all tests executed Ok! :o)\n\n");

	if (key) grg_key_free (gctx, key);
	if (tmp) grg_tmpfile_close (gctx, tmp);
	if (gctx) grg_context_free (gctx);

	return 0;
}

