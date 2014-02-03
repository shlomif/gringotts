/*  libGringotts - generic data encoding (crypto+compression) library
 *  (c) 2002, Germano Rizzo <mano@pluto.linux.it>
 *
 *  libgrg_crypt.h - internal-use (opaque) parameters definition
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

#ifndef LIBGRG_CRYPT_H
#define LIBGRG_CRYPT_H

#include "libgringotts.h"
#include "config.h"

//masks
#define GRG_ENCRYPT_MASK		0x70	//01110000
#define GRG_HASH_MASK			0x08	//00001000
#define GRG_COMP_TYPE_MASK		0x04	//00000100
#define GRG_COMP_LVL_MASK		0x03	//00000011

//use of small memory requirements in BZ2 decompression
#define USE_BZ2_SMALL_MEM		TRUE

//file format specs; do not touch these
#define LIBGRG_CRC_LEN			4
#define LIBGRG_DATA_DIM_LEN		4
#define LIBGRG_ALGO_LEN			1
#define LIBGRG_FILE_VERSION_LEN	1

#define LIBGRG_ALGO_POS			8	//HEADER_LEN + LIBGRG_FILE_VERSION_LEN + LIBGRG_CRC_LEN
#define LIBGRG_DATA_POS			9	//LIBGRG_ALGO_POS + LIBGRG_ALGO_LEN
#define LIBGRG_OVERHEAD			14	//LIBGRG_DATA_POS + LIBGRG_CRC_LEN + LIBGRG_DATA_DIM_LEN

#define LIBGRG_IV_SIZE_MIN		8	//for 3DES
#define LIBGRG_IV_SIZE_MAX		32	//for RIJNDAEL_256

#define FALSE	0
#define TRUE	!FALSE

unsigned char *grg2mcrypt (const grg_crypt_algo algo);

#endif
