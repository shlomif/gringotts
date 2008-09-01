/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_prefs.h - header file for grg_prefs.c
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

#ifndef GRG_PREFS_H
#define GRG_PREFS_H

#include <gtk/gtk.h>

gboolean grg_prefs_warn4overwrite;
gboolean grg_prefs_bak_files;
gboolean grg_prefs_splash;
gboolean grg_prefs_tray;
gboolean grg_prefs_clip_clear_on_close;
gboolean grg_prefs_clip_clear_on_quit;
gint grg_prefs_xpire;
gint grg_prefs_wipe_passes;
gint grg_prefs_mainwin_width, grg_prefs_mainwin_height;

gchar *get_pref_file (void);
void set_pref_file (const gchar * newval);
gchar *get_pref_font_string (void);
void set_pref_font_string (const gchar * newval);
void set_pref_font_string_from_editor (void);

void grg_pref_dialog (GtkWidget * parent);
void grg_prefs_update (void);
void grg_prefs_free (void);
void grg_prefs_reset_defaults (void);
#endif
