/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_safe.h - header file for grg_safe.c
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

#ifndef GRG_SAFE_H
#define GRG_SAFE_H

gboolean grg_mlockall_and_drop_root_privileges (void);
gboolean grg_security_filter (gboolean rootCheck);

void grg_security_monitor (void);

GtkWidget *grg_get_security_button (void);
gchar *grg_get_security_text (gchar * pattern);

gint grg_safe_open (gchar * path);

gpointer grg_malloc (gulong length);
gpointer grg_realloc (gpointer ptr, gulong length);
#endif
