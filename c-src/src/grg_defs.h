/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_defs.h - various declarations
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

#ifndef GRG_DEFS_H
#define GRG_DEFS_H

#include <glib.h>
#include <libgringotts.h>

#ifdef HAVE_CONFIG_H

#include "config.h"

#endif

#include <libintl.h>
#define _(String) \
	gettext (String)

#define GRGFREE(mem, dim) \
	grg_free (gctx, mem, dim)
#define GRGAFREE(mem) \
	grg_free (gctx, mem, -1)
#define STR_EQ(s1, s2) \
        (strcmp (s1, s2) == 0)

//mimick the behavour of isatty () if
//system doesn't have it but has ttyname ()
#ifndef HAVE_ISATTY
#ifdef HAVE_TTYNAME
#define isatty(fd) \
		(ttyname(fd) != NULL)
#define HAVE_ISATTY 1
#endif
#endif

//limits for preferences
#define EXP_TIME_MIN	1
#define EXP_TIME_MAX	730
#define EXP_TIME_DEF	30

#define WIPE_PASSES_MIN	1
#define WIPE_PASSES_MAX	32
#define WIPE_PASSES_DEF	8

//file descriptors
#define STDIN	0
#define STDOUT	1
#define STDERR	2

//time for the dialog to be redrawn
#define GRG_VISUAL_LATENCY 333	//ms
//time for the splash screen display
#define GRG_SPLASH_TIMEOUT 1750	//ms

//errors in grg_safe_open
#define GRG_OPEN_FILE_NOT_FOUND	-171
#define GRG_OPEN_FILE_IRREGULAR	-172
#define GRG_OPEN_SECURITY_FAULT	-173

//types of entry
#define SIMPLE_ENTRY	0
#define STRUCT_ENTRY	1

//models an entry item
struct grg_entry
{
	gchar *entryID;
	gchar *entryBody;
	GList *attach;
};

//models an attached file
struct grg_attachment
{
	gint ID;
	gchar *filename;
	glong filedim;
	gchar *comment;
	GRG_TMPFILE pointer;
};

//response
typedef enum
{
	GRG_YES,
	GRG_NO,
	GRG_CANCEL
}
grg_response;

//saveability
typedef enum
{
	GRG_SAVE_INACTIVE,
	GRG_SAVE_ACTIVE,
	GRG_SAVE_QUERY
}
grg_saveable;

//cut/copy/paste
typedef enum
{
	GRG_CUT,
	GRG_COPY,
	GRG_PASTE
}
grg_clip_action;

//returned OK
#define GRG_OK			0

//error
#define GRG_READ_INVALID_CHARSET_ERR	-101

//interface-specific constants
#define GRG_PAD			4

//internal encryption algorithm
#define SESSION_ALGO	MCRYPT_RIJNDAEL_128

//suffix to Gringotts files
#define SUFFIX		".grg"
#define SUFFIX_LEN	4

//suffix to add to backup files
#define BACKUP_SUFFIX	".bak"

//direction to move to
#define GRG_MV_FIRST	1
#define GRG_MV_NEXT		2
#define GRG_MV_PREV		3
#define GRG_MV_LAST		4

#endif
