# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Written by Shlomi Fish <shlomif@cpan.org> at 2019
# based on libgringotts by Germano Rizzo.
#
# Distributed under the terms of the GPL - version
# 2 or at your option any later version.

import os
import platform
import unittest

from cffi import FFI


class Gringotts(object):
    def __init__(self, ffi=None, lib=None):
        if ffi:
            self.ffi = ffi
            self.lib = lib
        else:
            self.ffi = FFI()
            self.lib = self.ffi.dlopen(
                "libgringotts." + (
                    "dll" if (platform.system() == 'Windows') else "so"))
            self.ffi.cdef('''
/*  libGringotts - generic data encoding (crypto+compression) library
 *  (c) 2002, Germano Rizzo <mano@pluto.linux.it>
 *
 *  libgringotts.h - general header file for libgringotts
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

// #include <sys/types.h>

// if you feel a wee bit confused please
// read the manual, tipically found at
// /usr/share/doc/libgringotts-<version>/manual.htm

// TYPEDEFS & ENUMERATIONS

//encryption algorithms
typedef enum
{
    GRG_RIJNDAEL_128 = 0x00,    //00000000
    GRG_AES = 0x00,        //alias for GRG_RIJNDAEL_128
    GRG_SERPENT = 0x10,    //00010000 (default)
    GRG_TWOFISH = 0x20,    //00100000
    GRG_CAST_256 = 0x30,    //00110000
    GRG_SAFERPLUS = 0x40,    //01000000
    GRG_LOKI97 = 0x50,    //01010000
    GRG_3DES = 0x60,    //01100000
    GRG_RIJNDAEL_256 = 0x70    //01110000
}
grg_crypt_algo;

//hashing algorithms
typedef enum
{
    GRG_SHA1 = 0x00,    //00000000
    GRG_RIPEMD_160 = 0x08    //00001000 (default)
}
grg_hash_algo;

//compression algorithm
typedef enum
{
    GRG_ZLIB = 0x00,    //00000000 (default)
    GRG_BZIP = 0x04        //00000100
}
grg_comp_algo;

//compression level
typedef enum
{
    GRG_LVL_NONE = 0x00,    //00000000
    GRG_LVL_FAST = 0x01,    //00000001
    GRG_LVL_GOOD = 0x02,    //00000010
    GRG_LVL_BEST = 0x03    //00000011 (default)
}
grg_comp_ratio;

//security level
typedef enum
{
    GRG_SEC_NORMAL,        //default
    GRG_SEC_PARANOIA
}
grg_security_lvl;

// ERROR CODES

//I/O Ok
#define GRG_OK                            0

//I/O Errors
//error codes in writing
#define GRG_WRITE_COMP_ERR                -2
#define GRG_WRITE_ENC_INIT_ERR            -4
#define GRG_WRITE_FILE_ERR                -6
//unused since 1.2.1 (don't use!)        -8
#define GRG_TMP_NOT_WRITEABLE            -10

//error codes in reading
#define GRG_READ_FILE_ERR                -1
#define GRG_READ_MMAP_ERR                -19
#define GRG_READ_MAGIC_ERR                -3
#define GRG_READ_CRC_ERR                -5
#define GRG_READ_PWD_ERR                -7
#define GRG_READ_ENC_INIT_ERR            -9
//unused since 1.2.1 (don't use!)        -11
#define GRG_READ_UNSUPPORTED_VERSION    -13
#define GRG_READ_COMP_ERR                -15
#define GRG_TMP_NOT_YET_WRITTEN            -17

//error codes in file shredding
#define    GRG_SHRED_CANT_OPEN_FILE        -51
#define GRG_SHRED_YET_LINKED            -52
#define GRG_SHRED_CANT_MMAP                -53

//generic error codes
#define GRG_MEM_ALLOCATION_ERR            -71
#define GRG_ARGUMENT_ERR                -72

typedef struct _grg_context *GRG_CTX;
typedef struct _grg_key *GRG_KEY;
typedef struct _grg_tmpfile *GRG_TMPFILE;

// General purpose functions

char *grg_get_version (void);
unsigned int grg_get_int_version (void);

// Security related functions

unsigned char *grg_rnd_seq (const GRG_CTX gctx, const unsigned int size);
void grg_rnd_seq_direct (const GRG_CTX gctx, unsigned char *toOverwrite,
    const unsigned int size);
unsigned char grg_rnd_chr (const GRG_CTX gctx);
void grg_free (const GRG_CTX gctx, void *alloc_data, const long dim);
double grg_ascii_pwd_quality (const char *pwd, const long pwd_len);
double grg_file_pwd_quality (const char *pwd_path);

// libGringotts context (GRG_CTX) related functions

GRG_CTX grg_context_initialize (const char *header,
                const grg_crypt_algo crypt_algo, const grg_hash_algo hash_algo,
                const grg_comp_algo comp_algo, const grg_comp_ratio comp_lvl,
                const grg_security_lvl sec_lvl);
GRG_CTX grg_context_initialize_defaults (const char *header);
void grg_context_free (GRG_CTX gctx);

grg_crypt_algo grg_ctx_get_crypt_algo (const GRG_CTX gctx);
grg_hash_algo grg_ctx_get_hash_algo (const GRG_CTX gctx);
grg_comp_algo grg_ctx_get_comp_algo (const GRG_CTX gctx);
grg_comp_ratio grg_ctx_get_comp_ratio (const GRG_CTX gctx);
grg_security_lvl grg_ctx_get_security_lvl (const GRG_CTX gctx);

void grg_ctx_set_crypt_algo (GRG_CTX gctx, const grg_crypt_algo crypt_algo);
void grg_ctx_set_hash_algo (GRG_CTX gctx, const grg_hash_algo hash_algo);
void grg_ctx_set_comp_algo (GRG_CTX gctx, const grg_comp_algo comp_algo);
void grg_ctx_set_comp_ratio (GRG_CTX gctx, const grg_comp_ratio comp_ratio);
void grg_ctx_set_security_lvl (GRG_CTX gctx,
                   const grg_security_lvl sec_level);

unsigned int grg_get_key_size_static (const grg_crypt_algo crypt_algo);
unsigned int grg_get_key_size (const GRG_CTX gctx);
unsigned int grg_get_block_size_static (const grg_crypt_algo crypt_algo);
unsigned int grg_get_block_size (const GRG_CTX gctx);

// libGringotts keyholder (GRG_KEY) related functions

GRG_KEY grg_key_gen (const char *pwd, const int pwd_len);
GRG_KEY grg_key_clone (const GRG_KEY src);
int grg_key_compare (const GRG_KEY k1, const GRG_KEY k2);
void grg_key_free (const GRG_CTX gctx, GRG_KEY key);

// File encryption/decryption functions
int grg_validate_file (const GRG_CTX gctx, const char *path);
int grg_update_gctx_from_file (GRG_CTX gctx, const char *path);
int grg_decrypt_file (const GRG_CTX gctx, const GRG_KEY keystruct,
              const char *path, unsigned char **origData,
              long *origDim);
int grg_encrypt_file (const GRG_CTX gctx, const GRG_KEY keystruct,
              const char *path,
              const unsigned char *origData, const long origDim);

// Their "direct" versions, requiring a file descriptor instead of a path
int grg_validate_file_direct (const GRG_CTX gctx, const int fd);
int grg_update_gctx_from_file_direct (GRG_CTX gctx, const int fd);
int grg_decrypt_file_direct (const GRG_CTX gctx, const GRG_KEY keystruct,
                 const int fd, unsigned char **origData,
                 long *origDim);
int grg_encrypt_file_direct (const GRG_CTX gctx, const GRG_KEY keystruct,
                 const int fd, const unsigned char *origData,
                 const long origDim);

// Memory encryption/decryption functions
int grg_validate_mem (const GRG_CTX gctx, const void *mem, const long memDim);
int grg_update_gctx_from_mem (GRG_CTX gctx, const void *mem,
                  const long memDim);
int grg_decrypt_mem (const GRG_CTX gctx, const GRG_KEY keystruct,
             const void *mem, const long memDim,
             unsigned char **origData, long *origDim);
int grg_encrypt_mem (const GRG_CTX gctx, const GRG_KEY keystruct, void **mem,
             long *memDim, const unsigned char *origData,
             const long origDim);

// Encrypted temporary files functions
GRG_TMPFILE grg_tmpfile_gen (const GRG_CTX gctx);
int grg_tmpfile_write (const GRG_CTX gctx, GRG_TMPFILE tf,
               const unsigned char *data, const long data_len);
int grg_tmpfile_read (const GRG_CTX gctx, const GRG_TMPFILE tf,
              unsigned char **data, long *data_len);
void grg_tmpfile_close (const GRG_CTX gctx, GRG_TMPFILE tf);

// Miscellaneous file functions
unsigned char *grg_encode64 (const unsigned char *in,
                 const int inlen, unsigned int *outlen);
unsigned char *grg_decode64 (const unsigned char *in,
                 const int inlen, unsigned int *outlen);

int grg_file_shred (const char *path, const int npasses);

''')
        # self.user = self.lib.freecell_solver_user_alloc()

    def new_fcs_user_handle(self):
        return self.__class__(ffi=self.ffi, lib=self.lib)

    def test1(self):
        gctx = self.lib.grg_context_initialize_defaults("GRG".encode('ascii'))
        key = self.lib.grg_key_gen("rindolf24".encode('utf-8'), -1)
        print(key)
        fd = os.open("./tests/data/rindolf.grg", os.O_RDONLY)
        print(fd)

        text = self.ffi.new('unsigned char * *')
        length = self.ffi.new('long *')
        errcode = self.lib.grg_decrypt_file_direct(
            gctx, key, fd, text, length)
        print(errcode)
        text_str = text[0]
        text_buf = self.ffi.buffer(text_str, length[0])

        print(bytes(text_buf))
        self.unittest.assertTrue(
            "<body>Go forth.</body>" in bytes(text_buf).decode('utf-8'))
        os.close(fd)
        self.lib.grg_key_free(gctx, key)
        print(gctx)
        self.lib.grg_context_free(gctx)


class MyTests(unittest.TestCase):
    def test1(self):
        g = Gringotts()
        g.unittest = self
        g.test1()


if __name__ == "__main__":
    # plan(7)
    from pycotap import TAPTestRunner
    suite = unittest.TestLoader().loadTestsFromTestCase(MyTests)
    TAPTestRunner().run(suite)
