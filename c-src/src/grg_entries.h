/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_entries.h - header file for grg_entries.c
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

#ifndef GRG_ENTRIES_H
#define GRG_ENTRIES_H

/* current element. */
/* MUST BE USED ONLY BY grg_attachs.h !!!! */
GList *current;

/* Appends a new entry to the list */
void grg_entries_append (void);

/* Removes the current entry and frees it */
void grg_entries_remove (void);


/* Tells if the current entry is the first one */
gboolean grg_entries_is_first (void);

/* Tells if the current entry is the last one */
gboolean grg_entries_is_last (void);

/* Tells if the current list is empty */
gboolean grg_entries_is_empty (void);


/* Goes to the first entry */
void grg_entries_first (void);

/* Goes to the previous entry */
void grg_entries_prev (void);

/* Goes to the next entry */
void grg_entries_next (void);

/* Goes to the last entry */
void grg_entries_last (void);

/* Goes to the specified entry, if possible */
void grg_entries_nth (gint pos);

/* Tells the position of the current entry in the list */
gint grg_entries_position (void);

/* Shifts one position up */
void grg_entries_raise (void);

/* Shifts one position down */
void grg_entries_sink (void);

/* Tells how many elements does the list contain */
guint grg_entries_n_el (void);

/* Tells how many files are attached to the current entry */
guint grg_entries_n_att (void);

/* Returns the title of the current entry. */
gchar *grg_entries_get_ID (void);

/* Returns the body text of the current entry. */
gchar *grg_entries_get_Body (void);

/* Stores the given title in the current entry. */
void grg_entries_set_ID (const gchar * ID);

/* Stores the given text as the body of the current entry. */
void grg_entries_set_Body (const gchar * Body);

/* Deletes and frees all the list */
void grg_entries_free (void);

/* Prints the entries to cmdline */
void grg_entries_print (gint ennum, gchar * enpage);

/* Saves the list into an encrypted file */
gint grg_entries_save (gchar * file, GRG_KEY key, GtkWidget * parent);

/* "de-serializes" a string into an entry list */
void grg_entries_load_from_string (gchar * str, GtkWidget * parent,
				   gboolean X);

/* Wrapper to file-related functions, to add UTF-8 handling */
gint grg_load_wrapper (gchar ** txt, GRG_KEY key, const gint fd,
		       const gchar * file);

/* Searches for a text in the entries. */
glong grg_entries_find (gchar * needle, glong offset, gboolean only_current,
			gboolean case_sens);

#endif
