/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_attachs.h - header file for grg_attachs.c
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

#ifndef GRG_ATTACHS_H
#define GRG_ATTACHS_H

#include <gtk/gtk.h>

gint current_attach_ID;

gint grg_attach_file (gchar * path, GtkWidget * parent);
void grg_remove_attachment (void);

gint grg_attach_content (void *cont, glong fdim, gchar * fname,
			 gchar * comment);
gint grg_get_content (struct grg_attachment *att, void **cont,
		      GtkWidget * parent);

gboolean grg_save_attachment (gchar * path, GtkWidget * parent);
void grg_info_attachment (GtkWidget * parent);
void grg_attach_list_free (GList * ceal);

enum
{
  ATTACHMENT_TITLE,
  ATTACHMENT_ID
};

void grg_attachment_fill_combo_box (GtkComboBox * combo_attach);

gboolean grg_attachment_change_comment (GtkWidget * parent);
#endif
