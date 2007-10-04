/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_widgets.c - various "custom" widgets used in Gringotts
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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <gtk/gtk.h>
#include <gdk-pixbuf/gdk-pixbuf.h>

#include "grg_defs.h"
#include "grg_pix.h"
#include "../pixmaps/gringotts.xpm"
#include "gringotts.h"
#include "grg_widgets.h"

gboolean mapIsUTF = FALSE;

/**
 * grg_msg:
 * @text: the text of the message to display
 * @msgt: the GtkMessageType of the message
 * @parent: the parent of the dialog to create
 *
 * Displays a dialog that shows a message.
 */
void
grg_msg (gchar * text, GtkMessageType msgt, GtkWidget * parent)
{
	GtkWidget *dialog =
		gtk_message_dialog_new (GTK_WINDOW (parent), GTK_DIALOG_MODAL,
					msgt,
					GTK_BUTTONS_OK, text);

	gtk_dialog_set_default_response (GTK_DIALOG (dialog),
					 GTK_RESPONSE_OK);
	gtk_dialog_run (GTK_DIALOG (dialog));

	gtk_widget_destroy (dialog);
}

void
report_err (gchar * msg, gboolean X, gboolean doquit, GtkWidget * parent)
{
	if (X)
		grg_msg (msg, GTK_MESSAGE_ERROR, parent);
	else
	{
		fprintf (stderr, "%s: %s\n", _("Error"), msg);
		if (doquit)
			emergency_quit (); //should suffice quit(1), but just in case... ;-)
	}
}

gboolean
return_submit (GtkWidget * w, GdkEventKey * ev, GtkWidget * w2)
{
	if (ev->keyval == 65293 || ev->keyval == 65421)
	{
		gtk_dialog_response (GTK_DIALOG (w2), GTK_RESPONSE_OK);
		return TRUE;
	}
	return FALSE;
}

/**
 * grg_input_dialog:
 * @title: the title of the input dialog
 * @qtext: the question to ask
 * @preset: the predefined answer, NULL if none
 * @is_pass: tells if the requested string is a password, to be obfuscated
 * @parent: the parent of the dialog to create
 *
 * Shows and manages a dialog that asks for a string.
 *
 * Returns: the answer string, or NULL if user pressed Cancel.
 */
gchar *
grg_input_dialog (gchar * title, gchar * qtext, gchar * preset,
		  gboolean is_pass, GtkWidget * parent)
{
	GtkWidget *dialog, *question, *label;
	gchar *ret = NULL;
	gint res;

	dialog = gtk_dialog_new_with_buttons (title, GTK_WINDOW (parent),
					      GTK_DIALOG_MODAL, GTK_STOCK_OK,
					      GTK_RESPONSE_OK,
					      GTK_STOCK_CANCEL,
					      GTK_RESPONSE_CANCEL, NULL);

	gtk_dialog_set_default_response (GTK_DIALOG (dialog),
					 GTK_RESPONSE_OK);

	gtk_container_set_border_width (GTK_CONTAINER (dialog), GRG_PAD);
	gtk_box_set_spacing (GTK_BOX (GTK_DIALOG (dialog)->vbox), GRG_PAD);

	label = gtk_label_new (qtext);

	question = gtk_entry_new ();
	g_signal_connect (G_OBJECT (question), "key-press-event",
			  G_CALLBACK (return_submit), (gpointer) dialog);
	gtk_entry_set_max_length (GTK_ENTRY (question), 32);
	if (preset != NULL)
		gtk_entry_set_text (GTK_ENTRY (question), preset);
	gtk_entry_set_visibility (GTK_ENTRY (question), !is_pass);

	gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox),
				     label);
	gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox),
				     question);

	gtk_widget_grab_focus (question);
	gtk_widget_show_all (dialog);

	res = gtk_dialog_run (GTK_DIALOG (dialog));

	if (res == GTK_RESPONSE_OK)
		ret = g_strdup ((gchar *)
				gtk_entry_get_text (GTK_ENTRY (question)));

	gtk_widget_destroy (dialog);

	return ret;
}

/**
 * grg_ask_dialog:
 * @title: the title of the dialog
 * @question: the question to ask
 * @allowcanc: if the dialog allows a cancel button or not
 * @parent: the parent of the dialog to create.
 *
 * Asks a question for a boolean answer.
 *
 * Returns: GRG_YES if yes, GRG_NO if no, GRG_CANCEL if user canceled
 */
grg_response
grg_ask_dialog (gchar * title, gchar * question, gboolean allowcanc,
		GtkWidget * parent)
{
	GtkWidget *dialog, *label;
	gint res;

	if (!allowcanc)
		dialog = gtk_dialog_new_with_buttons (title,
						      GTK_WINDOW (parent),
						      GTK_DIALOG_MODAL,
						      GTK_STOCK_YES,
						      GTK_RESPONSE_YES,
						      GTK_STOCK_NO,
						      GTK_RESPONSE_NO, NULL);
	else
		dialog = gtk_dialog_new_with_buttons (title,
						      GTK_WINDOW (parent),
						      GTK_DIALOG_MODAL,
						      GTK_STOCK_YES,
						      GTK_RESPONSE_YES,
						      GTK_STOCK_NO,
						      GTK_RESPONSE_NO,
						      GTK_STOCK_CANCEL,
						      GTK_RESPONSE_CANCEL,
						      NULL);

	gtk_dialog_set_default_response (GTK_DIALOG (dialog),
					 GTK_RESPONSE_OK);

	gtk_container_set_border_width (GTK_CONTAINER (dialog), GRG_PAD);
	gtk_box_set_spacing (GTK_BOX (GTK_DIALOG (dialog)->vbox), GRG_PAD);

	label = gtk_label_new (question);

	gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox),
				     label);

	gtk_widget_show_all (dialog);

	res = gtk_dialog_run (GTK_DIALOG (dialog));

	gtk_widget_destroy (dialog);

	switch (res)
	{
	case GTK_RESPONSE_YES:
		return GRG_YES;
	case GTK_RESPONSE_NO:
		return GRG_NO;
	case GTK_RESPONSE_CANCEL:
	default:
		return GRG_CANCEL;
	}
}

/**
 * grg_window_set_icon:
 * @w: the window to set the icon to
 *
 * Associates the Gringotts icon with the given window.
 */
void
grg_window_set_icon (GtkWindow * w)
{
	GdkPixbuf *gp = gdk_pixbuf_new_from_xpm_data (gringotts_xpm);
	GList *gl = NULL;

	g_list_append (gl, gp);
	gtk_window_set_icon (w, gp);
	gtk_window_set_default_icon_list (gl);

	g_list_free (gl);
	g_object_unref (G_OBJECT (gp));
}

/**
 * grg_find_dialog:
 */
gboolean
grg_find_dialog (gchar ** needle, gboolean * only_current,
		 gboolean * case_sens, GtkWindow * parent)
{
	GtkWidget *dialog, *question, *label, *chk1, *chk2;
	gint res;

	dialog = gtk_dialog_new_with_buttons (_("Find a string"),
					      GTK_WINDOW (parent),
					      GTK_DIALOG_MODAL, GTK_STOCK_OK,
					      GTK_RESPONSE_OK,
					      GTK_STOCK_CANCEL,
					      GTK_RESPONSE_CANCEL, NULL);

	gtk_dialog_set_default_response (GTK_DIALOG (dialog),
					 GTK_RESPONSE_OK);

	gtk_container_set_border_width (GTK_CONTAINER (dialog), 3);
	gtk_box_set_spacing (GTK_BOX (GTK_DIALOG (dialog)->vbox), 3);

	label = gtk_label_new (_("Enter the string to find:"));

	question = gtk_entry_new ();
	g_signal_connect (G_OBJECT (question), "key-press-event",
			  G_CALLBACK (return_submit), (gpointer) dialog);
	gtk_entry_set_max_length (GTK_ENTRY (question), 32);
	if (*needle)
		gtk_entry_set_text (GTK_ENTRY (question), *needle);

	chk1 = gtk_check_button_new_with_label (_
						("Search only in this entry"));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (chk1),
				      *only_current);

	chk2 = gtk_check_button_new_with_label (_("Case sensitive"));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (chk2), *case_sens);

	gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox),
				     label);
	gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox),
				     question);
	gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox),
				     chk1);
	gtk_box_pack_start_defaults (GTK_BOX (GTK_DIALOG (dialog)->vbox),
				     chk2);

	gtk_widget_grab_focus (question);
	gtk_widget_show_all (dialog);

	res = gtk_dialog_run (GTK_DIALOG (dialog));

	if (res != GTK_RESPONSE_OK)
	{
		gtk_widget_destroy (dialog);
		return FALSE;
	}

	g_free (*needle);
	*needle = g_strdup (gtk_entry_get_text (GTK_ENTRY (question)));
	*only_current =
		gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (chk1));
	*case_sens = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (chk2));
	
	gtk_widget_destroy (dialog);

	return TRUE;
}

static gboolean
exit_wait_timed (gpointer void_w)
{
    GtkWidget * w = (GtkWidget *)void_w;
	gtk_dialog_response (GTK_DIALOG (w), GTK_RESPONSE_DELETE_EVENT);
	return FALSE;
}

GtkWidget *
grg_wait_msg (gchar * reason, GtkWidget * parent)
{
	GtkWidget *wait, *lbl_wait, *hbox_wait, *img_wait;
	GdkPixbuf *pix;
	gchar *msg = g_strdup_printf ("%s,\n%s...", _("Please wait"), reason);

	wait = gtk_dialog_new_with_buttons (_("Please wait"),
					    GTK_WINDOW (parent),
					    GTK_DIALOG_MODAL |
					    GTK_DIALOG_DESTROY_WITH_PARENT,
					    NULL);
	gtk_widget_show_all (wait);
	gtk_dialog_set_has_separator (GTK_DIALOG (wait), FALSE);
	gtk_container_set_border_width (GTK_CONTAINER (wait), GRG_PAD);

	hbox_wait = gtk_hbox_new (FALSE, GRG_PAD * 2);
	gtk_box_pack_start (GTK_BOX (GTK_DIALOG (wait)->vbox), hbox_wait,
			    FALSE, FALSE, 0);

	pix = gdk_pixbuf_new_from_xpm_data (wait_xpm);
	img_wait = gtk_image_new_from_pixbuf (pix);
	gtk_misc_set_alignment (GTK_MISC (img_wait), (gfloat) 0.5,
				(gfloat) 0.0);
	g_object_unref (G_OBJECT (pix));
	gtk_box_pack_start (GTK_BOX (hbox_wait), img_wait, FALSE, FALSE, 0);

	lbl_wait = gtk_label_new (msg);
	g_free (msg);
	gtk_box_pack_start (GTK_BOX (hbox_wait), lbl_wait, FALSE, FALSE, 0);

	gtk_widget_show_all (wait);

	g_timeout_add (GRG_VISUAL_LATENCY, exit_wait_timed,
			 wait);
	gtk_dialog_run (GTK_DIALOG (wait));

	return wait;
}

void
grg_wait_message_change_reason (GtkWidget * wait, gchar * reason)
{
	GList *child1, *child2;
	gchar *msg = g_strdup_printf ("%s,\n%s...", _("Please wait"), reason);

	child1 = gtk_container_get_children (GTK_CONTAINER
					     (GTK_DIALOG (wait)->vbox));
	child2 = gtk_container_get_children (GTK_CONTAINER (child1->data));

	gtk_label_set_text (GTK_LABEL (child2->next->data), msg);

	g_free (msg);
	g_list_free (child1);
	g_list_free (child2);

	g_timeout_add (GRG_VISUAL_LATENCY, exit_wait_timed,
			 wait);
	gtk_dialog_run (GTK_DIALOG (wait));
}

void
grg_display_file (gchar * file)
{
	static const gchar *commands[] = { "htmlview %s &>/dev/null",
		"galeon %s &>/dev/null",
		"mozilla %s &>/dev/null",
		"netscape %s &>/dev/null",
		"konqueror --mimetype \"text/plain\" %s &>/dev/null",
		"gnome-terminal --hide-menubar -x less %s &>/dev/null",
		"gnome-terminal -x less %s &>/dev/null",
		"konsole -e less %s &>/dev/null",
		"gless --geometry=500x400+50+50 %s &>/dev/null",
		"xterm -e less %s &>/dev/null",
		"/usr/X11R6/bin/xterm -e less %s &>/dev/null",
		NULL
	};			//add eterm, opera

	gchar *command = NULL;
	gint resp = -1, i = 0;

	if (!g_file_test (file, G_FILE_TEST_EXISTS))
	{
		report_err (_("The file does not exist"), TRUE, FALSE, NULL);
		return;
	}

	//iterates on the available visualizers list until it finds stng useable
	while (resp && commands[i])
	{
		gchar *quote = g_shell_quote (file);
		command = g_strdup_printf (commands[i], quote);
		g_free (quote);
		resp = system (command);
		g_free (command);
		i++;
	}
}

GtkWidget * 
grg_toolbar_insert_stock(GtkToolbar *toolbar,
    const gchar *stock_id,
    const char *tooltip_text,
    GtkSignalFunc callback,
    gpointer user_data,
    gint position)
{
    GtkToolItem * item;

    item = gtk_tool_button_new_from_stock(stock_id);

    gtk_tool_item_set_tooltip_text (item, tooltip_text);

    g_signal_connect (item, "clicked",
			          callback, user_data);

    gtk_toolbar_insert (toolbar, item, position);

    return GTK_WIDGET (item);
}
