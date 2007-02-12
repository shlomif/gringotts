/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  gringotts.h - header file for gringotts.c
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

#ifndef GRINGOTTS_H
#define GRINGOTTS_H

#include "grg_defs.h"

GList *garbage;

GRG_CTX gctx;
glong pwdbirth;

	/*callbacks for menu items */

//Displays a "not yet implemented" message box
//void nyi(void);

	/*menu File */

//Creates a new document.
void do_new (void);

//Displays a file loading dialog, then calls load.
void meta_load (void);

//Calls load_file() with the specified file arg.
void meta_load_file (gpointer callback_data, gchar * callback_action);

//Saves the current version of the opened document.
void save (void);

//Displays the Save As dialog, then calls save_as.
void meta_save_as (void);

//Reverts to last saved version.
void revert (void);

//Closes the opened document.
grg_response file_close (void);

//exits
void quit (gint code);
void emergency_quit (void);

//Asks for save if not saved, and then exits.
void meta_quit (void);

void meta_saveable (gpointer data, gpointer user_data);

	/*menu Edit */

//Appends a new entry.
void insert (void);

//Deletes the current entry.
void del (void);

//Calls the change password dialog.
void chpwd (void);

//Displays the preferences window.
void launch_prefs (void);

	/*menu Navigation */

//Displays the entry in the specified direction.
void move_around (gpointer callback_data, guint callback_action);

//Calls the list window.
void meta_list (void);

	/*menu Tools */

//Securely wipe a file
void wipe_file (void);

	/*menu Help */

//Displays the `About' box.
void about (void);

//Performs an action about saveability.
gboolean update_saveable (grg_saveable mode);

gchar *get_editor_font (void);
void set_editor_font (const gchar * font_desc);

void update (void);

#endif
