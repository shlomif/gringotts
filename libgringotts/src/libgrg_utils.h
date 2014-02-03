/*  libGringotts - generic data encoding (crypto+compression) library
 *  (c) 2002, Germano Rizzo <mano@pluto.linux.it>
 *
 *  libgrg_utils.h - header file for libgrg_utils.c
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

#ifndef LIBGRG_UTILS_H
#define LIBGRG_UTILS_H

unsigned char *grg_long2char (const long seed);
long grg_char2long (const unsigned char *seed);
unsigned char *grg_memdup (const unsigned char *src, const long len);
unsigned char *grg_memconcat (const int count, ...);
void grg_XOR_mem (unsigned char *src, int src_len, unsigned char *mask,
		  int mask_len);
void grg_unsafe_free (void *alloc_data);

#endif
