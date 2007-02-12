/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_menus.c - builds the menu widget(s)
 *  Author: Nicolas Pouillon, Germano Rizzo
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

#include <gtk/gtk.h>

#include "gringotts.h"
#include "grg_menus.h"
#include "grg_recent_dox.h"
#include "grg_defs.h"
#include "grg_safe.h"
#include "grg_entries_vis.h"
#include "grg_widgets.h"

#include <gdk/gdkkeysyms.h>

#define NEW_MENU_ITEM(var, text, cb, data, parent, img, key, mod) \
	var = gtk_image_menu_item_new_with_mnemonic(text); \
	gtk_menu_shell_append (GTK_MENU_SHELL (parent), var); \
	image = gtk_image_new_from_stock(img, GTK_ICON_SIZE_MENU ); \
	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(var), image ); \
	if(key > 0) \
		gtk_widget_add_accelerator (var, "activate", accel_group, key, mod, GTK_ACCEL_VISIBLE); \
	g_signal_connect (var, "activate", G_CALLBACK(cb), data);

#define NEW_FILE_MENU_ITEM(number, text) \
	{ \
		gchar *ufile = g_filename_to_utf8 ((gchar *) text, -1, NULL, NULL, NULL); \
		gchar *txt = g_strdup_printf("_%d -  %s", number+1, ufile); \
		gchar *text_copy = g_strdup(text); \
		menu[number] = gtk_menu_item_new_with_mnemonic(txt); \
		gtk_menu_shell_insert (GTK_MENU_SHELL (file), menu[number], 9+number); \
		g_signal_connect (menu[number], "activate", G_CALLBACK(meta_load_file), text_copy); \
		g_list_append (garbage, text_copy); \
		g_free(txt); g_free (ufile); \
	}

#define NEW_MENU_SEPARATOR(parent) \
	gtk_menu_shell_append (GTK_MENU_SHELL (parent), gtk_separator_menu_item_new());

static GtkWidget *file, *menu[GRG_RECENT_LIMIT];

static void
faq (void)
{
	grg_display_file (DOCDIR "/FAQ");
}

static void
readme (void)
{
	grg_display_file (DOCDIR "/README");
}

/**
 * grg_menu_create:
 * @window: the window to add the menu to
 *
 * Makes a menubar, within a handlebox, and returns the GtkWidget
 *
 * Returns: the menubar widget
 */
GtkWidget *
grg_menu_create (GtkWidget * window)
{
	/* the single menu item widgets are defined in the grg_menus.h file */

	GtkWidget *menubar, *mhandle, *wid;
	GtkWidget *edit, *nav, *tools, *help;
	GtkWidget *image;
	GSList *recent;
	gint i = 0;
	GtkAccelGroup *accel_group;

	accel_group = gtk_accel_group_new ();
	gtk_window_add_accel_group (GTK_WINDOW (window), accel_group);

	menubar = gtk_menu_bar_new ();
	mhandle = gtk_handle_box_new ();

	gtk_container_add (GTK_CONTAINER (mhandle), menubar);
	gtk_widget_show (menubar);

	/*
	 * File menu
	 */

	file = gtk_menu_new ();

	wid = gtk_tearoff_menu_item_new ();
	gtk_menu_shell_append (GTK_MENU_SHELL (file), wid);

	NEW_MENU_ITEM (bnew, _("_New"), do_new, NULL, file, GTK_STOCK_NEW,
		       GDK_N, GDK_CONTROL_MASK);
	NEW_MENU_SEPARATOR (file);
	NEW_MENU_ITEM (bopen, _("_Open"), meta_load, NULL, file,
		       GTK_STOCK_OPEN, GDK_O, GDK_CONTROL_MASK);
	NEW_MENU_ITEM (bsave, _("_Save"), save, NULL, file, GTK_STOCK_SAVE,
		       GDK_S, GDK_CONTROL_MASK);
	NEW_MENU_ITEM (bsas, _("Save _As"), meta_save_as, NULL, file,
		       GTK_STOCK_SAVE_AS, GDK_A, GDK_CONTROL_MASK);
	NEW_MENU_ITEM (brev, _("_Revert"), revert, NULL, file,
		       GTK_STOCK_REVERT_TO_SAVED, GDK_R, GDK_CONTROL_MASK);
	NEW_MENU_ITEM (bclose, _("_Close"), file_close, NULL, file,
		       GTK_STOCK_CLOSE, GDK_W, GDK_CONTROL_MASK);
	NEW_MENU_SEPARATOR (file);
	recent = grg_recent_dox;
	while ((recent != NULL) && (i < GRG_RECENT_LIMIT))
	{
		NEW_FILE_MENU_ITEM (i, recent->data);
		recent = recent->next;
		i++;
	}
	NEW_MENU_SEPARATOR (file);
	NEW_MENU_ITEM (bquit, _("_Quit"), meta_quit, NULL, file,
		       GTK_STOCK_QUIT, GDK_Q, GDK_CONTROL_MASK);


	wid = gtk_menu_item_new_with_mnemonic (_("_File"));
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (wid), file);
	gtk_menu_shell_append (GTK_MENU_SHELL (menubar), wid);

	/*
	 * Edit menu
	 */

	edit = gtk_menu_new ();

	wid = gtk_tearoff_menu_item_new ();
	gtk_menu_shell_append (GTK_MENU_SHELL (edit), wid);

	NEW_MENU_ITEM (badd, _("Add"), insert, NULL, edit, GTK_STOCK_ADD,
		       GDK_D, GDK_CONTROL_MASK);
	NEW_MENU_ITEM (brem, _("Remove"), del, NULL, edit, GTK_STOCK_REMOVE,
		       GDK_E, GDK_CONTROL_MASK);
	NEW_MENU_SEPARATOR (edit);
	NEW_MENU_ITEM (bcut, _("Cu_t"), cucopa, GINT_TO_POINTER (GRG_CUT),
		       edit, GTK_STOCK_CUT, GDK_X, GDK_CONTROL_MASK);
	NEW_MENU_ITEM (bcop, _("_Copy"), cucopa, GINT_TO_POINTER (GRG_COPY),
		       edit, GTK_STOCK_COPY, GDK_C, GDK_CONTROL_MASK);
	NEW_MENU_ITEM (bpaste, _("_Paste"), cucopa,
		       GINT_TO_POINTER (GRG_PASTE), edit, GTK_STOCK_PASTE,
		       GDK_V, GDK_CONTROL_MASK);
	NEW_MENU_SEPARATOR (edit);
	NEW_MENU_ITEM (bfind, _("_Find"), find, GINT_TO_POINTER (FALSE), edit,
		       GTK_STOCK_FIND, GDK_F, GDK_CONTROL_MASK);
	NEW_MENU_ITEM (bfinda, _("Find a_gain"), find, GINT_TO_POINTER (TRUE),
		       edit, GTK_STOCK_FIND, GDK_F3, 0);
	NEW_MENU_SEPARATOR (edit);
	NEW_MENU_ITEM (bpwd, _("Change Pass_word"), chpwd, NULL, edit,
		       GTK_STOCK_CONVERT, GDK_C,
		       GDK_SHIFT_MASK | GDK_CONTROL_MASK);
	NEW_MENU_SEPARATOR (edit);
	NEW_MENU_ITEM (bpref, _("P_references"), launch_prefs, NULL, edit,
		       GTK_STOCK_PREFERENCES, GDK_P, GDK_CONTROL_MASK);

	wid = gtk_menu_item_new_with_mnemonic (_("_Edit"));
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (wid), edit);
	gtk_menu_shell_append (GTK_MENU_SHELL (menubar), wid);

	/*
	 * Navigation menu
	 */

	nav = gtk_menu_new ();

	wid = gtk_tearoff_menu_item_new ();
	gtk_menu_shell_append (GTK_MENU_SHELL (nav), wid);

	NEW_MENU_ITEM (bmfirst, _("_First"), move_around,
		       GINT_TO_POINTER (GRG_MV_FIRST), nav,
		       GTK_STOCK_GOTO_FIRST, GDK_I, GDK_CONTROL_MASK);
	NEW_MENU_ITEM (bmback, _("_Back"), move_around,
		       GINT_TO_POINTER (GRG_MV_PREV), nav, GTK_STOCK_GO_BACK,
		       GDK_K, GDK_CONTROL_MASK);
	NEW_MENU_ITEM (bmfor, _("For_ward"), move_around,
		       GINT_TO_POINTER (GRG_MV_NEXT), nav,
		       GTK_STOCK_GO_FORWARD, GDK_W,
		       GDK_SHIFT_MASK | GDK_CONTROL_MASK);
	NEW_MENU_ITEM (bmlast, _("_Last"), move_around,
		       GINT_TO_POINTER (GRG_MV_LAST), nav,
		       GTK_STOCK_GOTO_LAST, GDK_T, GDK_CONTROL_MASK);
	NEW_MENU_SEPARATOR (nav);
	NEW_MENU_ITEM (bmind, _("_Index"), meta_list, NULL, nav,
		       GTK_STOCK_INDEX, GDK_X,
		       GDK_SHIFT_MASK | GDK_CONTROL_MASK);

	wid = gtk_menu_item_new_with_mnemonic (_("_Navigation"));
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (wid), nav);
	gtk_menu_shell_append (GTK_MENU_SHELL (menubar), wid);

	/*
	 * Tools menu
	 */

	tools = gtk_menu_new ();

	wid = gtk_tearoff_menu_item_new ();
	gtk_menu_shell_append (GTK_MENU_SHELL (tools), wid);

	NEW_MENU_ITEM (bwipe, _("_Wipe file"), wipe_file, NULL, tools,
		       GTK_STOCK_CLEAR, GDK_D,
		       GDK_SHIFT_MASK | GDK_CONTROL_MASK);

	wid = gtk_menu_item_new_with_mnemonic (_("_Tools"));
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (wid), tools);
	gtk_menu_shell_append (GTK_MENU_SHELL (menubar), wid);

	/*
	 * Help menu
	 */

	help = gtk_menu_new ();

	wid = gtk_tearoff_menu_item_new ();
	gtk_menu_shell_append (GTK_MENU_SHELL (help), wid);

	NEW_MENU_ITEM (babo, _("_Security monitor"), grg_security_monitor,
		       NULL, help, GTK_STOCK_HELP, GDK_S,
		       GDK_SHIFT_MASK | GDK_CONTROL_MASK);
	NEW_MENU_SEPARATOR (help);
	NEW_MENU_ITEM (babo, "_README", readme, NULL, help, GTK_STOCK_HELP,
		       GDK_R, GDK_SHIFT_MASK | GDK_CONTROL_MASK);
	NEW_MENU_ITEM (babo, "_FAQ", faq, NULL, help, GTK_STOCK_HELP,
		       GDK_F, GDK_SHIFT_MASK | GDK_CONTROL_MASK);
	NEW_MENU_SEPARATOR (help);
	NEW_MENU_ITEM (babo, _("_About"), about, NULL, help, GTK_STOCK_HELP,
		       GDK_B, GDK_CONTROL_MASK);

	wid = gtk_menu_item_new_with_mnemonic (_("_Help"));
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (wid), help);
	gtk_menu_item_set_right_justified (GTK_MENU_ITEM (wid), TRUE);
	gtk_menu_shell_append (GTK_MENU_SHELL (menubar), wid);

	return mhandle;
}

void
grg_menu_update (void)
{
	gint i = 0;
	GSList *tmp = grg_recent_dox;

	while (menu[i] && (i < GRG_RECENT_LIMIT))
	{
		gtk_widget_destroy (menu[i]);
		menu[i] = NULL;
		i++;
	}

	i = 0;
	while ((tmp != NULL) && (i < GRG_RECENT_LIMIT))
	{
		NEW_FILE_MENU_ITEM (i, tmp->data);
		tmp = tmp->next;
		i++;
	}

	i = 0;
	while (menu[i])
	{
		gtk_widget_show (menu[i]);
		i++;
	}
}
