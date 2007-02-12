/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_widgets.h - header file for grg_widgets.c
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

#ifndef GRG_WIDGETS_H
#define GRG_WIDGETS_H

#include "grg_defs.h"

gboolean mapIsUTF;

//Shows and manages a dialog that asks for a string.
gchar *grg_input_dialog (gchar * title, gchar * qtext, gchar * preset,
			 gboolean is_pass, GtkWidget * parent);

//Displays a dialog that shows a message.
void grg_msg (gchar * text, GtkMessageType msgt, GtkWidget * parent);

//transparent X and non-X error reporting
void report_err (gchar * msg, gboolean X, gboolean doquit,
		 GtkWidget * parent);

//Asks a question for a boolean answer.
grg_response grg_ask_dialog (gchar * title, gchar * question, 
        gboolean allowcanc, GtkWidget * parent);

//Associates the Gringotts icon with the given window.
void grg_window_set_icon (GtkWindow * w);

gboolean grg_find_dialog (gchar ** needle, gboolean * only_current,
			  gboolean * case_sens, GtkWindow * parent);

//displays a "Wait..." window, to be destroyed at the end of waiting
GtkWidget *grg_wait_msg (gchar * reason, GtkWidget * parent);
void grg_wait_message_change_reason (GtkWidget * wait, gchar * reason);

//calls an external application to display a text file
void grg_display_file (gchar * file);

//callback to submit a form when enter is pressed
gboolean return_submit (GtkWidget * w, GdkEventKey * ev, GtkWidget * w2);

GtkWidget * 
grg_toolbar_insert_stock(GtkToolbar *toolbar,
    const gchar *stock_id,
    const char *tooltip_text,
    const char *tooltip_private_text,
    GtkSignalFunc callback,
    gpointer user_data,
    gint position);

extern GtkTooltips * tooltips;

#endif
