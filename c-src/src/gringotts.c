/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  gringotts.c - main program and interface
 *  Authors: Germano Rizzo, Nicholas Pouillon
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

#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>

#include <gtk/gtk.h>

#include "grg_defs.h"
#include "grg_pix.h"
#include "grg_entries.h"
#include "grg_entries_vis.h"
#include "grg_widgets.h"
#include "grg_list.h"
#include "grg_menus.h"
#include "grg_prefs.h"
#include "grg_prefs_io.h"
#include "grg_pwd.h"
#include "grg_safe.h"
#include "grg_recent_dox.h"
#include "grg_popt.h"
#include "grg_attachs.h"

#include <libgringotts.h>

#include "gringotts.h"

/* appends a stock item to a toolbar */
#define	TOOLBAR_INS_STOCK(tbar, stock, callback, tooltip) \
	grg_toolbar_insert_stock (GTK_TOOLBAR (tbar), stock, tooltip, \
		(GtkSignalFunc) callback, NULL, -1)

/* appends a stock item to a toolbar, assigning it to a widget */
#define	TOOLBAR_INS_STOCK_WIDGET(tbar, stock, callback, tooltip, wid) \
	wid = grg_toolbar_insert_stock (GTK_TOOLBAR (tbar), stock, tooltip, \
		(GtkSignalFunc) callback, NULL, -1)

/* appends a stock item to a toolbar, assigning it to a widget and passing a value to the callback */
#define	TOOLBAR_INS_STOCK_WIDGET_SIGNAL(tbar, stock, callback, tooltip, signal, wid) \
	wid = grg_toolbar_insert_stock (GTK_TOOLBAR (tbar), stock, tooltip, \
		(GtkSignalFunc) callback, GINT_TO_POINTER (signal), -1)

/* appends a space to a toolbar */
#define TOOLBAR_INS_SPACE(tbar) \
	my_toolbar_append_space (GTK_TOOLBAR (tbar))

/* - some menu buttons are never deactivated (i.e. Quit), so their widgets aren't really needed
 */

/*  general */
static GtkWidget *title, *win1, *edit, *lbl;

/*  toolbar Navigation */
static GtkWidget *bfirst, *bback, *bfor, *blast, *bind;

/*  others */
static GtkWidget *btitle;

/*  main toolbar  */
static GtkWidget *tnew, *topen, *tsave, *tclose;
static GtkWidget *tadd, *trem, *tcut, *tcopy, *tpast, *tfind, *tpref;
static GtkWidget *batadd, *batrem, *batsav, *batinf, *batchco;
static GtkComboBox *combo_attach;
static GtkListStore * combo_attach_list_store;

static gchar *grgfile = NULL, *caption = NULL;
static gboolean started = FALSE, gtk_loop_started = FALSE;
static gboolean created = FALSE;
static guint tout;
static GRG_KEY key;

GList *garbage = NULL;

GRG_CTX gctx = NULL;
glong pwdbirth = 0;

static void
my_toolbar_append_space (GtkToolbar * toolbar)
{
    GtkToolItem * separator;

    separator = gtk_separator_tool_item_new();

    gtk_toolbar_insert (toolbar, separator, -1);
}

/*
 * nyi:
 *
 * Displays a "not yet implemented" message box
 *
void
nyi (void)
{
	grg_msg (_("Sorry, this function hasn't been implemented yet"),
		 GTK_MESSAGE_ERROR, win1);
}*/

static void
garbage_collect (gpointer att, gpointer user_data)
{
	GRGAFREE (att);
}

/**
 * about:
 *
 * Displays the `About' box.
 */
void
about (void)
{
	gchar *info =
		g_strconcat (GRG_CAP_NAME, _(" version "), GRG_VERSION, "\n",
			     _("(c)"),
			     " 2002 Germano Rizzo <mano78@users.sourceforge.net> \n\n",
			     _("Authors"),
			     ":\n" "   Germano Rizzo <mano78@users.sourceforge.net>\n",
			     "   Nicolas Pouillon <nipo@ssji.net>\n" "\n",
			     _
			     ("Gringotts is a small but (hopely ;) useful utility that stores "
			      "sensitive data (passwords, credit card numbers, friends' "
			      "addresses) in an organized and most of all very secure form.\n"
			      "It uses libmcrypt and libmhash to provide a strong level of "
			      "encryption, just trying to be as trustworthy as possible.\n\n"
			      "This program is released under the GNU GPL, v.2 or later\n"
			      "See COPYING or go to http://www.gnu.org/copyleft/gpl.html"),
			     "\n\n" "libmcrypt ", _("(c)"),
			     " 1998,1999 Nikos Mavroyanopoulos\n" "libmhash ",
			     _("(c)"), " 2001 Nikos Mavroyanopoulos\n",
			     _("the name"),
			     " \"Gringotts\" ", _("(c)"),
			     " 1998 Joanne K. Rowling", NULL);

	grg_msg (info, GTK_MESSAGE_INFO, win1);
	g_free (info);
}
/*
void
attach_warn (void)
{
	grg_msg (_
		 ("This is a relatively new feature, so it's still under heavy"
		  "development... and may have some problem. In this case,"
		  "the stability and data safety should be good, but it lacks"
		  "quite much in speed. If you attach larger files, you may"
		  "have to wait a pretty huge deal of time. It depends from"
		  "case to case anyway; the best thing is to try it yourself. In"
		  "future releases of Gringotts we'll work also on this aspect."),
		 GTK_MESSAGE_WARNING, win1);
}
*/
/**
 * prefs:
 *
 * Displays the preferences window.
 */
void
launch_prefs (void)
{
	grg_pref_dialog (win1);
}

/**
 * quit:
 *
 * Exits the main application cycle, releasing the resources.
 */
void
quit (gint code)
{
	grg_key_free (gctx, key);
	key = NULL;
	g_free (grgfile);
	grgfile = NULL;
	g_free (caption);
	caption = NULL;
	if (gtk_loop_started)
		gtk_main_quit ();
	g_list_foreach (garbage, garbage_collect, NULL);
	g_list_free (garbage);
	grg_prefs_free ();
	grg_recent_dox_deinit ();
	entries_vis_deinit ();
	grg_context_free (gctx);
	exit (code);
}

/**
 * `Ungracefully' quits, shutting down all resources in a safe way
 */
void
emergency_quit (void)
{
	del_needle ();
	grg_entries_free ();
	quit(1);
}

/**
 * update_saveable:
 * @mode: the operation to perform:
 *        GRG_SAVE_ACTIVE -> activates all the save widgets.
 *        GRG_SAVE_INACTIVE -> deactivates all the save widgets.
 *        GRG_SAVE_QUERY -> query for saveability state.
 *
 * Performs an action about saveability.
 *
 * Returns: if GRG_SAVE_QUERY, the saveability state.
 */
gboolean
update_saveable (grg_saveable mode)
{
	static gboolean saveable = TRUE;
	gboolean nsaveable;

	if (mode == GRG_SAVE_QUERY)
		return saveable;

	if (started && grgfile)
	{
		gchar *ugrg =
			g_filename_to_utf8 (grgfile, -1, NULL, NULL, NULL);
		g_free (caption);
		if (mode == GRG_SAVE_ACTIVE)
		{
			caption = g_strconcat (ugrg, " *", NULL);
			g_free (ugrg);
		}
		else
			caption = ugrg;
		gtk_window_set_title (GTK_WINDOW (win1), caption);
	}

	nsaveable = (mode == GRG_SAVE_ACTIVE) && !grg_entries_is_empty ();
	if (nsaveable ^ saveable)
	{
		saveable = nsaveable;
		gtk_widget_set_sensitive (bsave, saveable);
		gtk_widget_set_sensitive (tsave, saveable);
		gtk_widget_set_sensitive (brev, saveable && grgfile
					  && !STR_EQ (grgfile,
						      _("New file")));
	}

	return saveable;
}

static gboolean
backup_file (gchar * filename)
{
	gchar *bak_name;
	struct stat s;
	gint res;

	res = lstat (filename, &s);
	if ((res < 0) || !S_ISREG (s.st_mode))	/*file non-existent or non-regular */
		return TRUE;

	bak_name = g_strconcat (filename, BACKUP_SUFFIX, NULL);

	res = lstat (bak_name, &s);
	if (((res == 0) && !S_ISREG (s.st_mode))
	    || rename (filename, bak_name))
	{
		g_free (bak_name);
		return FALSE;
	}

	g_free (bak_name);
	return TRUE;
}

/**
 * meta_saveable:
 * @data: unused
 * @user_data: a gpointer to the mode to pass to update_saveable().
 *
 * Controls if update_saveable() can be called, and if so calls it.
 */
void
meta_saveable (gpointer data, gpointer user_data)
{
	if (started)
		update_saveable ((grg_saveable) GPOINTER_TO_INT (user_data));
}

static void
update_combo_attach (void)
{
    grg_attachment_fill_combo_box (combo_attach);
}

/**
 * update:
 *
 * Updates various widgets (title of the window, button sensitivity...)
 */
/* FIXME: should be "static void" but it's (mis)called elsewhere */
void
update (void)
{
	static gchar *tlbl;
	gboolean isStuffed = !grg_entries_is_empty ();
	gboolean isAttachSelected;
	gboolean notFirst = !grg_entries_is_first ();
	gboolean notLast = !grg_entries_is_last ();
	gboolean moreThan1 = grg_entries_n_el () > 1;

	update_combo_attach ();
	/*current_attach_ID gets aligned only after grg_attach_get_menu */
	isAttachSelected = current_attach_ID > -1;

	gtk_widget_set_sensitive (btitle, isStuffed);
	gtk_widget_set_sensitive (bind, isStuffed);
	gtk_widget_set_sensitive (bsas, isStuffed);
	gtk_widget_set_sensitive (badd, isStuffed);
	gtk_widget_set_sensitive (tadd, isStuffed);
	gtk_widget_set_sensitive (bmind, isStuffed);
	gtk_widget_set_sensitive (bpwd, isStuffed);
	gtk_widget_set_sensitive (tclose, isStuffed);
	gtk_widget_set_sensitive (bclose, isStuffed);
	gtk_widget_set_sensitive (edit, isStuffed);
	gtk_widget_set_sensitive (bcut, isStuffed);
	gtk_widget_set_sensitive (tcut, isStuffed);
	gtk_widget_set_sensitive (bcop, isStuffed);
	gtk_widget_set_sensitive (tcopy, isStuffed);
	gtk_widget_set_sensitive (bpaste, isStuffed);
	gtk_widget_set_sensitive (tpast, isStuffed);
	gtk_widget_set_sensitive (bfind, isStuffed);
	gtk_widget_set_sensitive (tfind, isStuffed);
	gtk_widget_set_sensitive (bpwd, isStuffed);

	gtk_widget_set_sensitive (batadd, isStuffed);

	gtk_widget_set_sensitive (batrem, isAttachSelected);
	gtk_widget_set_sensitive (batsav, isAttachSelected);
	gtk_widget_set_sensitive (batinf, isAttachSelected);
	gtk_widget_set_sensitive (batchco, isAttachSelected);
	gtk_widget_set_sensitive (GTK_WIDGET (combo_attach), isAttachSelected);

	gtk_label_set_text (GTK_LABEL (title),
			    isStuffed ? grg_entries_get_ID () : GRG_CAP_NAME
			    " " GRG_VERSION);
	
	gtk_widget_hide(edit);
	edit=get_updated_sheet(isStuffed);
	gtk_widget_show(edit);

	gtk_widget_set_sensitive (bfor, notLast);
	gtk_widget_set_sensitive (blast, notLast);
	gtk_widget_set_sensitive (bmfor, notLast);
	gtk_widget_set_sensitive (bmlast, notLast);

	gtk_widget_set_sensitive (bback, notFirst);
	gtk_widget_set_sensitive (bfirst, notFirst);
	gtk_widget_set_sensitive (bmback, notFirst);
	gtk_widget_set_sensitive (bmfirst, notFirst);

	gtk_widget_set_sensitive (brem, moreThan1);
	gtk_widget_set_sensitive (trem, moreThan1);

	gtk_widget_set_sensitive (bfinda, has_needle ());

	tlbl = g_strdup_printf ("%d/%d", grg_entries_position () + 1,
				grg_entries_n_el ());
	gtk_label_set_text (GTK_LABEL (lbl), tlbl);
	g_free (tlbl);

	gtk_window_set_title (GTK_WINDOW (win1), caption);
}

void save (void);

/**
 * file_close:
 *
 * Closes the opened document.
 *
 * Returns: GRG_YES if all has gone well, GRG_NO if error, GRG_CANCEL if user canceled
 */
grg_response
file_close (void)
{
	if (grg_entries_is_empty ())
		return GRG_NO;

	if (update_saveable (GRG_SAVE_QUERY))
	{
		grg_response resp = grg_ask_dialog (_("Save?"),
						    _
						    ("Some changes have not been saved.\nDo you wish to save them now?"),
						    TRUE, win1);
		switch (resp)
		{
		case GRG_CANCEL:
			return resp;
		case GRG_YES:
			save ();
		case GRG_NO:
		default:
			if (grg_prefs_clip_clear_on_close)
				clear_clipboard ();
		}
	}
	grg_entries_free ();
	del_needle ();
	grg_key_free (gctx, key);
	key = NULL;
	g_free (grgfile);
	grgfile = NULL;
	g_free (caption);
	caption = g_strconcat (GRG_CAP_NAME, " ", GRG_VERSION, NULL);
	update_saveable (GRG_SAVE_INACTIVE);
	update ();

	return GRG_YES;
}

/**
 * meta_quit:
 *
 * Asks for save if not saved, and then exits.
 */
void
meta_quit (void)
{
	if (file_close () == GRG_CANCEL)
		return;

	quit (0);
}

/**
 * revert:
 *
 * Reverts to last saved version.
 */
void
revert (void)
{
	if (update_saveable (GRG_SAVE_QUERY) &&
	    (grg_ask_dialog
	     (_("Confirm"),
	      _("You'll lose all the changes from\nlast save! Are you sure?"),
	      FALSE, win1) == GRG_YES))
	{
		gchar *tmp = NULL;
		GtkWidget *wait = grg_wait_msg (_("loading"), win1);

		gint err, fd;

		fd = grg_safe_open (grgfile);

		if (fd == GRG_OPEN_FILE_IRREGULAR)
		{
			grg_msg (_
				 ("You've selected a directory or a symlink"),
				 GTK_MESSAGE_ERROR, win1);
			return;
		}

		if (fd < 3)
		{
			grg_msg (_("The selected file doesn't exists"),
				 GTK_MESSAGE_ERROR, win1);
			return;
		}

		err = grg_load_wrapper (&tmp, key, fd, grgfile);

		close (fd);

		if (err)
			gtk_widget_destroy (wait);

		switch (err)
		{
		case GRG_OK:
		{
			grg_wait_message_change_reason (wait,
							_("assembling data"));
			grg_entries_load_from_string (tmp, win1, TRUE);
			grg_wait_message_change_reason (wait,
							_("cleaning up"));
			gtk_widget_destroy (wait);
			update_saveable (GRG_SAVE_INACTIVE);
			update ();
			break;
		}

		case GRG_MEM_ALLOCATION_ERR:
		{
			printf("error: malloc failed. Probably this indicates a memory "
			   "problem, such as resource exhaustion. Attempting "
			   "to exit cleanly...");
			emergency_quit();
		}
		
		case GRG_ARGUMENT_ERR:
		{
			grg_msg (_
				 ("Gringotts internal error. Cannot finish operation."),
				 GTK_MESSAGE_ERROR, win1);
			break;
		}

		case GRG_READ_MAGIC_ERR:
		case GRG_READ_UNSUPPORTED_VERSION:
		case GRG_READ_CRC_ERR:
		case GRG_READ_PWD_ERR:
		case GRG_READ_COMP_ERR:
		case GRG_READ_INVALID_CHARSET_ERR:
		{
			grg_msg (_("The file appears to be corrupted!"),
				 GTK_MESSAGE_ERROR, win1);
			break;
		}
#ifdef GRG_READ_TOO_BIG_ERR
		case GRG_READ_TOO_BIG_ERR:
		{
			grg_msg (_("File is too big"), GTK_MESSAGE_ERROR,
				 win1);
			break;
		}
#endif
		case GRG_READ_FILE_ERR:
		{
			grg_msg (_("Uh-oh! I can't read from the file!"),
				 GTK_MESSAGE_ERROR, win1);
			break;
		}

		case GRG_READ_ENC_INIT_ERR:
		{
			grg_msg (_
				 ("Problem with libmcrypt, probably a faulty installation"),
				 GTK_MESSAGE_ERROR, win1);
			break;
		}

		default:
#ifdef MAINTAINER_MODE
			g_assert_not_reached ();
#else
			grg_msg (_
				 ("Gringotts internal error. Cannot finish operation."),
				 GTK_MESSAGE_ERROR, win1);
#endif
			break;
		}

		GRGAFREE (tmp);
		tmp = NULL;
	}

	if ((grg_prefs_xpire > 0) && pwdbirth &&
	    (grg_prefs_xpire * 86400L < time (NULL) - pwdbirth))
		grg_msg (_
			 ("The current password is expired.\nYou should change it, or modify this "
			  "setting in the preferences"), GTK_MESSAGE_WARNING,
			 win1);
}

/**
 * load_file:
 * @filename: a filename (in the local encoding).
 *
 * Loads a gringotts file.
 */
static void
load_file (gchar * input_filename)
{
	GtkWidget *wait;
	GRG_KEY tmpkey;
	gint err, fd;
	gchar *res;
	struct stat buf1, buf2;
    gchar * abs_filename = NULL;

	if (!input_filename || !*input_filename)
		goto cleanup;

	fd = grg_safe_open (input_filename);

	if (fd == GRG_OPEN_FILE_IRREGULAR)
	{
		grg_msg (_("You've selected a directory or a symlink"),
			 GTK_MESSAGE_ERROR, win1);
		goto cleanup;
	}

	if (fd < 3)
	{
		grg_msg (_("The selected file doesn't exists"),
			 GTK_MESSAGE_ERROR, win1);
		goto cleanup;
	}

	/* if this and the opened one are the very same file, fall back on revert() */
	if (grgfile &&
	    !STR_EQ (grgfile, _("New file")) &&
	    (lstat (grgfile, &buf1) == 0) &&
	    (fstat (fd, &buf2) == 0) &&
	    (buf1.st_dev == buf2.st_dev) && (buf1.st_ino == buf2.st_ino))
	{
		close (fd);
		revert ();
		goto cleanup;
	}

	if (g_path_is_absolute (input_filename))
    {
        abs_filename = g_strdup(input_filename);
    }
    else
	{
		abs_filename = (gchar *) grg_malloc (PATH_MAX);

		realpath (input_filename, abs_filename);
	}

	if (file_close () == GRG_CANCEL)
		goto cleanup;

	err = grg_validate_file_direct (gctx, fd);

	switch (err)
	{
	case GRG_OK:
		break;

	case GRG_READ_MAGIC_ERR:
	case GRG_READ_UNSUPPORTED_VERSION:
	{
		close (fd);
		grg_msg (_
			 ("This file doesn't seem to be a valid Gringotts one!"),
			 GTK_MESSAGE_ERROR, win1);
		goto cleanup;
	}

	case GRG_MEM_ALLOCATION_ERR:
	{
		close (fd);
		printf("error: malloc failed. Probably this indicates a memory "
		   "problem, such as resource exhaustion. Attempting "
		   "to exit cleanly...");
		emergency_quit();
	}
	
	case GRG_ARGUMENT_ERR:
	{
		close (fd);
		grg_msg (_
			 ("Gringotts internal error. Cannot finish operation."),
			 GTK_MESSAGE_ERROR, win1);
		goto cleanup;
	}

	case GRG_READ_FILE_ERR:
	{
		close (fd);
		grg_msg (_("Uh-oh! I can't read from the file!"),
			 GTK_MESSAGE_ERROR, win1);
		goto cleanup;
	}

	case GRG_READ_CRC_ERR:
	case GRG_READ_COMP_ERR:
	{
		close (fd);
		grg_msg (_("The file appears to be corrupted!"),
			 GTK_MESSAGE_ERROR, win1);
		goto cleanup;
	}
#ifdef GRG_READ_TOO_BIG_ERR
	case GRG_READ_TOO_BIG_ERR:
	{
		close (fd);
		grg_msg (_("File is too big"), GTK_MESSAGE_ERROR, win1);
		goto cleanup;
	}
#endif
	default:
	{
		if (err < 0)
		{
			close (fd);
			grg_msg (_
				 ("Gringotts internal error. Cannot finish operation."),
				 GTK_MESSAGE_ERROR, win1);
			goto cleanup;
		}
	}
	}

	while (TRUE)
	{
		gboolean doret = FALSE, exit = FALSE;
		gchar *msg = NULL;

		tmpkey = grg_ask_pwd_dialog (win1);

		if (!tmpkey)
		{
			close (fd);
			goto cleanup;
		}

		wait = grg_wait_msg (_("loading"), win1);

		err = grg_load_wrapper (&res, tmpkey, fd, abs_filename);

		if (err < 0)
			gtk_widget_destroy (wait);

		switch (err)
		{
		case GRG_OK:
		{
			grg_wait_message_change_reason (wait,
							_("assembling data"));
			grg_entries_load_from_string (res, win1, TRUE);
			grg_wait_message_change_reason (wait,
							_("cleaning up"));
			GRGAFREE (res);
			gtk_widget_destroy (wait);
			res = NULL;
			exit = TRUE;
		}
			break;

		case GRG_MEM_ALLOCATION_ERR:
		{
			printf("error: malloc failed. Probably this indicates a memory "
			   "problem, such as resource exhaustion. Attempting "
			   "to exit cleanly...");
			emergency_quit();
		}
		
		case GRG_ARGUMENT_ERR:
		{
			msg = _("Gringotts internal error. Cannot finish operation.");
			doret = TRUE;
			break;
		}

		case GRG_READ_PWD_ERR:
		{
			msg = _("Wrong password! Re-enter it");
		}
			break;

		case GRG_READ_ENC_INIT_ERR:
		{
			msg = _("Problem with libmcrypt, probably a faulty installation");
			doret = TRUE;
		}
			break;

		case GRG_READ_INVALID_CHARSET_ERR:
		{
			msg = _("Saved data contain invalid UTF-8 chars");
			doret = TRUE;
		}
			break;

			/* just to be sure... */
		default:
		{
			if (err < 0)
			{
				msg = _("Gringotts internal error. Cannot finish operation.");
				doret = TRUE;
			}
		}
		}

		if (msg)
			grg_msg (msg, GTK_MESSAGE_ERROR, win1);

		if (doret)
		{
			close (fd);
			grg_key_free (gctx, tmpkey);
			goto cleanup;
		}

		if (exit)
			break;
	}

	close (fd);

	g_free (grgfile);
	grgfile = NULL;

	grgfile = g_strdup (abs_filename);
	grg_key_free (gctx, key);
	key = grg_key_clone (tmpkey);
	grg_key_free (gctx, tmpkey);
	tmpkey = NULL;

	update ();
	update_saveable (GRG_SAVE_INACTIVE);
	if ((grg_prefs_xpire > 0) && pwdbirth &&
	    (grg_prefs_xpire * 86400L < time (NULL) - pwdbirth))
		grg_msg (_
			 ("The current password is expired.\nYou should change it, or modify this "
			  "setting in the preferences"), GTK_MESSAGE_WARNING,
			 win1);

cleanup:
    if (abs_filename)
    {
        g_free (abs_filename);
    }
    return;
}

/**
 * meta_load:
 *
 * Displays a file loading dialog, then calls load_file().
 */
void
meta_load (void)
{
    GtkWidget *file_chooser;
	gint response;

    file_chooser = gtk_file_chooser_dialog_new (_("Open..."),
            GTK_WINDOW(win1),
            GTK_FILE_CHOOSER_ACTION_OPEN,
            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
            GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
            NULL);

	response = gtk_dialog_run (GTK_DIALOG (file_chooser));
    if (response == GTK_RESPONSE_ACCEPT)
    {
		/*
         * It may appear a stupid duplication, but it's very important
         * to avoid two file selectors at the same time, so one should
         * be destroyed *before* calling load_file
         * */
        char *fname;

        fname = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (file_chooser));
        gtk_widget_destroy (file_chooser);
        load_file (fname);

        g_free (fname);
    }
    else
    {
        gtk_widget_destroy (file_chooser);
    }
}

/**
 * meta_load_file:
 *
 * Calls load_file() with the specified file arg.
 * used by the recent files menu.
 */
void
meta_load_file (gpointer callback_data, gchar * callback_action)
{
	load_file (callback_action);
}

/**
 * move_around:
 *
 * Displays the entry in the specified direction.
 */
void
move_around (gpointer callback_data, guint callback_action)
{
	sync_entry ();
	switch (callback_action)
	{
	case GRG_MV_NEXT:
		grg_entries_next ();
		break;
	case GRG_MV_PREV:
		grg_entries_prev ();
		break;
	case GRG_MV_FIRST:
		grg_entries_first ();
		break;
	case GRG_MV_LAST:
		grg_entries_last ();
		break;
	}
	update ();
}

/**
 * do_new:
 *
 * Creates a new document.
 */
void
do_new (void)
{
	GRG_KEY tmpkey;

	if (file_close () == GRG_CANCEL)
		return;

	g_assert (GTK_IS_WIDGET (win1));

	tmpkey = grg_new_pwd_dialog (GTK_WIDGET (win1));

	if (!tmpkey)
	{
		grg_msg (_("You must enter a valid password!"),
			 GTK_MESSAGE_ERROR, win1);
		return;
	}

	grg_key_free (gctx, key);

	g_free (grgfile);
	grgfile = g_strdup (_("New file"));

	if (!grg_entries_is_empty ())
		grg_entries_free ();

	key = grg_key_clone (tmpkey);
	grg_key_free (gctx, tmpkey);
	tmpkey = NULL;

	grg_entries_append ();
	grg_entries_set_ID (_("My first page"));
	grg_entries_first ();
	pwdbirth = time (NULL);
	update_saveable (GRG_SAVE_ACTIVE);
	update ();
}

/**
 * retitle:
 *
 * Gives the entry another title.
 */
static void
retitle (void)
{
	gchar *new = grg_input_dialog (_("New title..."),
				       _("New title for this entry:"),
				       grg_entries_get_ID (), FALSE, win1);
	if (new)
	{
		sync_entry ();
		grg_entries_set_ID (new);
		GRGAFREE (new);
		new = NULL;
		update_saveable (GRG_SAVE_ACTIVE);
		update ();
	}
}

/**
 * save_as:
 * @fpath: the path to save to
 * @overwrite_confirm: specifies whether to ask for overwriting or not
 *
 * Saves a file with another name.
 */
static void
save_as (const gchar * fpath)
{
#if 0
	GtkWidget *wait;
#endif
	gchar *tmpfile;
	gint err, fd;
	gboolean is_current = STR_EQ (fpath, grgfile);	/*Am I saving the current file? */

	tmpfile = g_strdup (fpath);

	if (!is_current)
	{
		if (memcmp
		    (fpath + strlen (fpath) - SUFFIX_LEN, SUFFIX,
		     SUFFIX_LEN) != 0)
		{
			gchar *tmp = g_strconcat (tmpfile, SUFFIX, NULL);
			g_free (tmpfile);
			tmpfile = g_strdup (tmp);
			g_free (tmp);
		}

		fd = grg_safe_open (tmpfile);

		if (fd == GRG_OPEN_FILE_IRREGULAR)
		{
			if (fd > 0)
				close (fd);
			grg_msg (_
				 ("I can't overwrite a directory or a symlink"),
				 GTK_MESSAGE_ERROR, win1);
			g_free (tmpfile);
			return;
		}

		if (grg_prefs_warn4overwrite
		    && (fd != GRG_OPEN_FILE_NOT_FOUND)
		    && (grg_ask_dialog (_("Overwrite?"),
					_
					("Do you want to overwrite the existing file?"),
					FALSE, win1) != GRG_YES))
		{
			if (fd > 0)
				close (fd);
			g_free (tmpfile);
			return;
		}

		if (fd > 0)
			close (fd);
	}

	if (grg_prefs_bak_files && !backup_file (tmpfile))
		grg_msg (_("Couldn't backup old file"), GTK_MESSAGE_WARNING,
			 win1);

	sync_entry ();

	err = grg_entries_save (tmpfile, key, win1);

	switch (err)
	{
	case GRG_OK:
	{
		if (!is_current)
		{
			if (grgfile)
				g_free (grgfile);
			grgfile = g_strdup (tmpfile);
		}
		update_saveable (GRG_SAVE_INACTIVE);
		break;
	}

	case GRG_MEM_ALLOCATION_ERR:
	{
		g_free (tmpfile);
		printf("error: malloc failed. Probably this indicates a memory "
		   "problem, such as resource exhaustion. Attempting "
		   "to exit cleanly...");
		emergency_quit();
	}
	
	case GRG_ARGUMENT_ERR:
	{
		grg_msg (_
			 ("Gringotts internal error. Cannot finish operation."),
			 GTK_MESSAGE_ERROR, win1);
		g_free (tmpfile);
		break;
	}

	case GRG_WRITE_COMP_ERR:
	{
		grg_msg (_("Error in compression! Probably a zlib problem"),
			 GTK_MESSAGE_ERROR, win1);
		g_free (tmpfile);
		break;
	}

	case GRG_WRITE_FILE_ERR:
	{
		grg_msg (_("Uh-oh! I can't write to the file!"),
			 GTK_MESSAGE_ERROR, win1);
		g_free (tmpfile);
		break;
	}

	case GRG_WRITE_ENC_INIT_ERR:
	{
		grg_msg (_
			 ("Problem with libmcrypt, probably a faulty installation"),
			 GTK_MESSAGE_ERROR, win1);
		g_free (tmpfile);
		break;
	}
#ifdef GRG_WRITE_TOO_BIG_ERR
	case GRG_WRITE_TOO_BIG_ERR:
	{
		grg_msg (_("Too many data to write"), GTK_MESSAGE_ERROR,
			 win1);
		g_free (tmpfile);
		break;
	}
#endif
	default:
#ifdef MAINTAINER_MODE
		g_assert_not_reached ();
#else
		grg_msg (_("Gringotts internal error. Cannot finish operation."), 
			GTK_MESSAGE_ERROR, win1);
#endif
		break;
	}
	g_free (tmpfile);
}

/**
 * meta_save_as:
 *
 * Displays the Save As dialog, then calls save_as().
 */
void
meta_save_as (void)
{
    GtkWidget *file_chooser;
    gint response;
    file_chooser = gtk_file_chooser_dialog_new (_("Save as...."),
                                      GTK_WINDOW(win1),
                                      GTK_FILE_CHOOSER_ACTION_SAVE,
                                      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                      GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
                                      NULL);
    gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (file_chooser), TRUE);
    response = gtk_dialog_run (GTK_DIALOG (file_chooser));
    if (response == GTK_RESPONSE_ACCEPT)
    {
        char * filename;

        filename = gtk_file_chooser_get_filename
            (GTK_FILE_CHOOSER (file_chooser));
        save_as (filename);
        g_free(filename);
    }
    gtk_widget_destroy (file_chooser);
}

/**
 * save:
 *
 * Saves the current version of the opened document, if any.
 */
void
save (void)
{
	if ((!grgfile) || STR_EQ (grgfile, _("New file")))
		meta_save_as ();
	else
		save_as (grgfile);
}

/**
 * insert:
 *
 * Appends a new entry.
 */
void
insert (void)
{
	gchar *new = grg_input_dialog (_("Title..."),
				       _("Title for the new entry:"),
				       _("New"),
				       FALSE, win1);

	sync_entry ();

	if (new)
	{
		grg_entries_append ();
		grg_entries_set_ID (new);
		GRGAFREE (new);
		update_saveable (GRG_SAVE_ACTIVE);
		update ();
	}
}

/**
 * del:
 *
 * Deletes the current entry.
 */
void
del (void)
{
	if (grg_ask_dialog
	    (_("Confirm..."),
	     _("Are you sure you want to remove this entry?"), FALSE,
	     win1) == GRG_YES)
	{
		grg_entries_remove ();
		update_saveable (GRG_SAVE_ACTIVE);
		update ();
	}
}

/**
 * chpwd:
 *
 * Calls the change password dialog.
 */
void
chpwd (void)
{
	GRG_KEY tmpkey, verkey;

	verkey = grg_ask_pwd_dialog (win1);

	if (!verkey || !grg_key_compare (verkey, key))
    {
        grg_msg (_("Wrong password"), GTK_MESSAGE_ERROR, win1);
        if (verkey)
        {
            grg_key_free (gctx, verkey);
            verkey = NULL;
        }
        return;
    }

	grg_key_free (gctx, verkey);
	verkey = NULL;

	tmpkey = grg_new_pwd_dialog (win1);

	if (tmpkey)
	{
		grg_key_free (gctx, key);
		key = grg_key_clone (tmpkey);
		grg_key_free (gctx, tmpkey);
		tmpkey = NULL;
		grg_msg (_("Password successfully changed"), GTK_MESSAGE_INFO,
			 win1);
		pwdbirth = time (NULL);
		update_saveable (GRG_SAVE_ACTIVE);
	}
}

/**
 * meta_list:
 *
 * Calls the list window.
 */
void
meta_list (void)
{
	sync_entry ();
	grg_list_run ();
	update ();
}

static void
destroy_splash (GtkWidget * w, GdkEvent * ev, GtkWidget * w2)
{
	gtk_widget_destroy (w2);
	g_source_remove (tout);
}

static gboolean
destroy_splash_timed (gpointer void_w)
{
    GtkWidget * w;

    w = (GtkWidget *)void_w;
	gtk_widget_destroy (w);
	return FALSE;
}

/**
 * grg_splash:
 * @parent: The parent window to put this into
 *
 * Builds a splash screen
 */
static GtkWidget *
grg_splash (GtkWidget * parent)
{
	GtkWidget *spwin, *spimg, *spebox;
	GdkPixbuf *spix;

	spwin = gtk_window_new (GTK_WINDOW_POPUP);
	gtk_window_set_transient_for (GTK_WINDOW (spwin),
				      GTK_WINDOW (parent));
	gtk_window_set_position (GTK_WINDOW (spwin),
				 GTK_WIN_POS_CENTER_ON_PARENT);
	gtk_window_set_modal (GTK_WINDOW (spwin), TRUE);

	spebox = gtk_event_box_new ();

	spix = gdk_pixbuf_new_from_xpm_data (splash_xpm);
	spimg = gtk_image_new_from_pixbuf (spix);
	g_object_unref (G_OBJECT (spix));
	gtk_widget_grab_focus (spimg);

	gtk_container_add (GTK_CONTAINER (spebox), spimg);
	gtk_container_add (GTK_CONTAINER (spwin), spebox);

	g_signal_connect (G_OBJECT (spebox), "button-press-event",
			  G_CALLBACK (destroy_splash), spwin);

	tout = g_timeout_add (GRG_SPLASH_TIMEOUT,
				(GSourceFunc) destroy_splash_timed, spwin);

	return spwin;
}

static void
attach_file (void)
{
    GtkWidget *file_chooser;
	gint response;
	gchar *selection = NULL;

	sync_entry ();

    file_chooser = gtk_file_chooser_dialog_new (_("Select file..."),
            GTK_WINDOW(win1),
            GTK_FILE_CHOOSER_ACTION_OPEN,
            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
            GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
            NULL);

    response = gtk_dialog_run (GTK_DIALOG (file_chooser));
    if (response == GTK_RESPONSE_ACCEPT)
    {
		/*
         * It may appear a stupid duplication, but it's very important
         * to avoid two file selectors at the same time, so one should
         * be destroyed *before* calling load_file
         * */
        selection = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (file_chooser));
    }

    gtk_widget_destroy (file_chooser);
	if (response != GTK_RESPONSE_ACCEPT)
		return;
	response = grg_attach_file (selection, win1);
	GRGAFREE (selection);
	if (response < 0)	/*didn't change anything */
		return;

	update_saveable (GRG_SAVE_ACTIVE);
	update ();
}

static void
detach_file (void)
{
	if (grg_ask_dialog (_("Confirm"),
			    _
			    ("After this, there's no way to\nrecover the file. Are you sure?"),
			    FALSE, win1) == GRG_NO)
		return;

	sync_entry ();

	grg_remove_attachment ();

	update_saveable (GRG_SAVE_ACTIVE);
	update ();
}

static void
save_attached_file (void)
{
    GtkWidget *file_chooser;
    gint response;
    gchar *selection = NULL;

    file_chooser = gtk_file_chooser_dialog_new (_("Save as...."),
                                      GTK_WINDOW(win1),
                                      GTK_FILE_CHOOSER_ACTION_SAVE,
                                      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                      GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
                                      NULL);

    response = gtk_dialog_run (GTK_DIALOG (file_chooser));
	if (response == GTK_RESPONSE_ACCEPT)
    {
		selection = gtk_file_chooser_get_filename
            (GTK_FILE_CHOOSER (file_chooser));
    }
	gtk_widget_destroy (file_chooser);
	if (response != GTK_RESPONSE_ACCEPT)
    {
		return;
    }
	grg_save_attachment (selection, win1);
	GRGAFREE (selection);
}

void
wipe_file (void)
{
    GtkWidget *file_chooser, *wait;
	gint response;
    gchar *selection = NULL;

    file_chooser = gtk_file_chooser_dialog_new (_("File to wipe"),
            GTK_WINDOW(win1),
            GTK_FILE_CHOOSER_ACTION_OPEN,
            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
            GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
            NULL);

	response = gtk_dialog_run (GTK_DIALOG (file_chooser));
    if (response == GTK_RESPONSE_ACCEPT)
    {
		selection = gtk_file_chooser_get_filename (
                GTK_FILE_CHOOSER (file_chooser)
                );
    }

    gtk_widget_destroy (file_chooser);

	if (response != GTK_RESPONSE_ACCEPT)
    {
		return;
    }

	if (!g_file_test (selection, G_FILE_TEST_IS_REGULAR))
	{
		g_free (selection);
		grg_msg (_("The file does not exist"), GTK_MESSAGE_ERROR,
			 win1);
	}

	if (grg_ask_dialog
	    (_("Confirm..."),
	     _("Are you sure you want to wipe this file?\n"
	       "Its content will be securely erased, so no\n"
	       "recover is possible."), FALSE, win1) != GRG_YES)
	{
		g_free (selection);
		return;
	}

	wait = grg_wait_msg (_("wiping file"), win1);

	response = grg_file_shred (selection, grg_prefs_wipe_passes);

	gtk_widget_destroy (wait);

	g_free (selection);

	if (response < 0)
		grg_msg (_("File wiping failed"), GTK_MESSAGE_ERROR, win1);
}

static void
info_attached_file (void)
{
	grg_info_attachment (win1);
}

static void
change_attach_comment (void)
{
	sync_entry ();
	if (grg_attachment_change_comment (win1))
		update_saveable (GRG_SAVE_ACTIVE);
}

gchar *
get_editor_font (void)
{
	PangoContext *editorFont = gtk_widget_get_pango_context (edit);
	PangoFontDescription *fdesc =
		pango_context_get_font_description (editorFont);
	return pango_font_description_to_string (fdesc);
}

void
set_editor_font (const gchar * font_desc)
{
	PangoFontDescription *fdesc =
		pango_font_description_from_string (font_desc);
	gtk_widget_modify_font (edit, fdesc);
	pango_font_description_free (fdesc);
}

/**
 * grg_interface:
 *
 * Builds and "activates" the Gringotts main interface.
 */
static void
grg_interface (void)
{
	GtkWidget *vbox, *hbox, *scrollbox, *scroll, *menu;
	GtkWidget *tbar_nav, *handle_nav, *tbar_main, *handle_main;
	GtkWidget *tbar_attach, *handle_attach;
	GtkSizeGroup *resizer;
	gchar *str, *fdesc;
	PangoFontDescription *pfd;
    GtkCellRenderer *cell;

	/* window */
	win1 = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	grg_window_set_icon (GTK_WINDOW (win1));

	caption = g_strconcat (GRG_CAP_NAME, " ", GRG_VERSION, NULL);

	gtk_container_set_border_width (GTK_CONTAINER (win1), GRG_PAD);
	g_signal_connect (G_OBJECT (win1), "destroy-event",
			  G_CALLBACK (meta_quit), NULL);
	g_signal_connect (G_OBJECT (win1), "delete-event",
			  G_CALLBACK (meta_quit), NULL);
	g_signal_connect (G_OBJECT (win1), "destroy", G_CALLBACK (meta_quit),
			  NULL);

	/* the multi-line text widget */
	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll),
					     GTK_SHADOW_ETCHED_IN);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
					GTK_POLICY_AUTOMATIC,
					GTK_POLICY_AUTOMATIC);
	
	gtk_widget_set_size_request (scroll, 400, 300);
	
	edit = get_updated_sheet (FALSE);
	
	gtk_container_add (GTK_CONTAINER (scroll), edit);

	/* the title widget */
	title = gtk_label_new ("");
	gtk_misc_set_alignment (GTK_MISC (title), 0.1, 0.5);
	btitle = gtk_button_new_with_mnemonic (_("E_dit..."));
	g_signal_connect (G_OBJECT (btitle), "clicked", G_CALLBACK (retitle),
			  NULL);
	pfd = pango_font_description_new ();
	pango_font_description_set_weight (pfd, PANGO_WEIGHT_BOLD);
	gtk_widget_modify_font (title, pfd);
	pango_font_description_free (pfd);
	lbl = gtk_label_new ("");

	/* the "navigation" lateral toolbar */
	tbar_nav = gtk_toolbar_new ();
	gtk_toolbar_set_style (GTK_TOOLBAR (tbar_nav), GTK_TOOLBAR_ICONS);
	gtk_toolbar_set_orientation (GTK_TOOLBAR (tbar_nav),
				     GTK_ORIENTATION_VERTICAL);
	handle_nav = gtk_handle_box_new ();
	gtk_handle_box_set_handle_position (GTK_HANDLE_BOX (handle_nav),
					    GTK_POS_TOP);
	gtk_container_add (GTK_CONTAINER (handle_nav), tbar_nav);

	TOOLBAR_INS_STOCK_WIDGET_SIGNAL (tbar_nav, GTK_STOCK_GOTO_LAST,
					 move_around, _("Go to last entry"),
					 GRG_MV_LAST, blast);
	TOOLBAR_INS_STOCK_WIDGET_SIGNAL (tbar_nav, GTK_STOCK_GO_FORWARD,
					 move_around, _("Go to next entry"),
					 GRG_MV_NEXT, bfor);

	TOOLBAR_INS_SPACE (tbar_nav);

	TOOLBAR_INS_STOCK_WIDGET (tbar_nav, GTK_STOCK_INDEX, meta_list,
				  _("View index"), bind);

	TOOLBAR_INS_SPACE (tbar_nav);

	TOOLBAR_INS_STOCK_WIDGET_SIGNAL (tbar_nav, GTK_STOCK_GO_BACK,
					 move_around,
					 _("Go to previous entry"),
					 GRG_MV_PREV, bback);
	TOOLBAR_INS_STOCK_WIDGET_SIGNAL (tbar_nav, GTK_STOCK_GOTO_FIRST,
					 move_around, _("Go to first entry"),
					 GRG_MV_FIRST, bfirst);

	/* size group for "left column" */
	resizer = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);
	gtk_size_group_add_widget (resizer, btitle);
	gtk_size_group_add_widget (resizer, tbar_nav);

	/*the "main" toolbar */
	tbar_main = gtk_toolbar_new ();
	gtk_toolbar_set_style (GTK_TOOLBAR (tbar_main), GTK_TOOLBAR_ICONS);
	handle_main = gtk_handle_box_new ();
	gtk_container_add (GTK_CONTAINER (handle_main), tbar_main);

	str = grg_get_security_text (_("Security level: %s"));

    {
        GtkToolItem * button;
        button = gtk_tool_button_new (grg_get_security_button(), _("Security"));

        gtk_tool_item_set_tooltip_text (button, str);
        
        g_signal_connect (button, "clicked",
            grg_security_monitor, NULL);
        
        gtk_toolbar_insert (GTK_TOOLBAR (tbar_main), button, -1);
    }
	g_free (str);

	TOOLBAR_INS_SPACE (tbar_main);

	TOOLBAR_INS_STOCK_WIDGET (tbar_main, GTK_STOCK_NEW, do_new,
				  _("New document"), tnew);

	TOOLBAR_INS_SPACE (tbar_main);

	TOOLBAR_INS_STOCK_WIDGET (tbar_main, GTK_STOCK_OPEN, meta_load,
				  _("Open document"), topen);
	TOOLBAR_INS_STOCK_WIDGET (tbar_main, GTK_STOCK_SAVE, save,
				  _("Save document"), tsave);
	TOOLBAR_INS_STOCK_WIDGET (tbar_main, GTK_STOCK_CLOSE, file_close,
				  _("Close document"), tclose);

	TOOLBAR_INS_SPACE (tbar_main);

	TOOLBAR_INS_STOCK_WIDGET_SIGNAL (tbar_main, GTK_STOCK_CUT, cucopa,
					 _("Cut selection"), GRG_CUT, tcut);
	TOOLBAR_INS_STOCK_WIDGET_SIGNAL (tbar_main, GTK_STOCK_COPY, cucopa,
					 _("Copy selection"), GRG_COPY,
					 tcopy);
	TOOLBAR_INS_STOCK_WIDGET_SIGNAL (tbar_main, GTK_STOCK_PASTE, cucopa,
					 _("Paste selection"), GRG_PASTE,
					 tpast);

	TOOLBAR_INS_SPACE (tbar_main);

	TOOLBAR_INS_STOCK_WIDGET_SIGNAL (tbar_main, GTK_STOCK_FIND, find,
					 _("Search for text"), FALSE, tfind);

	TOOLBAR_INS_SPACE (tbar_main);

	TOOLBAR_INS_STOCK_WIDGET (tbar_main, GTK_STOCK_ADD, insert,
				  _("Add an entry"), tadd);
	TOOLBAR_INS_STOCK_WIDGET (tbar_main, GTK_STOCK_REMOVE, del,
				  _("Remove this entry"), trem);

	TOOLBAR_INS_SPACE (tbar_main);

	TOOLBAR_INS_STOCK_WIDGET (tbar_main, GTK_STOCK_PREFERENCES,
				  launch_prefs, _("Preferences"), tpref);

	TOOLBAR_INS_SPACE (tbar_main);

	TOOLBAR_INS_STOCK (tbar_main, GTK_STOCK_QUIT, meta_quit,
			   _("Quit Gringotts"));

	/*attachment handling toolbar */
	tbar_attach = gtk_toolbar_new ();
	gtk_toolbar_set_style (GTK_TOOLBAR (tbar_attach), GTK_TOOLBAR_ICONS);
	handle_attach = gtk_handle_box_new ();
	gtk_container_add (GTK_CONTAINER (handle_attach), tbar_attach);
	scrollbox = gtk_vbox_new (FALSE, GRG_PAD);
	gtk_box_pack_start (GTK_BOX (scrollbox), handle_attach, FALSE, FALSE,
			    1);
	gtk_box_pack_start (GTK_BOX (scrollbox), scroll, TRUE, TRUE, 1);

    {
        GtkToolItem * button;

        button = gtk_tool_item_new ();
        gtk_container_add (GTK_CONTAINER (button), 
                gtk_label_new (_("Attached files")));
        
        gtk_tool_item_set_tooltip_text (button, "");

        gtk_toolbar_insert (GTK_TOOLBAR (tbar_attach), button, -1);
    }

/*	TOOLBAR_INS_STOCK (tbar_attach, GTK_STOCK_DIALOG_WARNING, attach_warn,
			   _("Important informations\non this feature"));*/
	TOOLBAR_INS_STOCK_WIDGET (tbar_attach, GTK_STOCK_ADD, attach_file,
				  _("Add a new attachment"), batadd);
	TOOLBAR_INS_STOCK_WIDGET (tbar_attach, GTK_STOCK_REMOVE, detach_file,
				  _("Remove this attachment"), batrem);
	TOOLBAR_INS_STOCK_WIDGET (tbar_attach, GTK_STOCK_SAVE,
				  save_attached_file,
				  _("Save this attachment"), batsav);
	TOOLBAR_INS_STOCK_WIDGET (tbar_attach, GTK_STOCK_DIALOG_INFO,
				  info_attached_file,
				  _("Info on this attachment"), batinf);
	TOOLBAR_INS_STOCK_WIDGET (tbar_attach, GTK_STOCK_CONVERT,
				  change_attach_comment, _("Change comment"),
				  batchco);

    combo_attach_list_store =
        gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);
    combo_attach =
        GTK_COMBO_BOX (gtk_combo_box_new_with_model (
                GTK_TREE_MODEL (combo_attach_list_store)
                ));

    cell = gtk_cell_renderer_text_new ();
    gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (combo_attach), cell, TRUE);
    gtk_cell_layout_set_attributes (GTK_CELL_LAYOUT (combo_attach), cell,
                                    "text", ATTACHMENT_TITLE,
                                    NULL);

    grg_attachment_fill_combo_box (combo_attach);
    {
        GtkToolItem * button;

        button = gtk_tool_item_new ();
        gtk_container_add (GTK_CONTAINER (button), 
                GTK_WIDGET (combo_attach));
        
        gtk_tool_item_set_tooltip_text (button, _("List of attached files"));

        gtk_toolbar_insert (GTK_TOOLBAR (tbar_attach), button, -1);
    }

	vbox = gtk_vbox_new (FALSE, 1);
	gtk_widget_show (vbox);

	menu = grg_menu_create (win1);
	gtk_box_pack_start (GTK_BOX (vbox), menu, FALSE, TRUE, 1);

	gtk_box_pack_start (GTK_BOX (vbox), handle_main, FALSE, TRUE, 1);

	hbox = gtk_hbox_new (FALSE, 1);
	gtk_box_pack_start (GTK_BOX (hbox), btitle, FALSE, TRUE, 1);
	gtk_box_pack_start (GTK_BOX (hbox), title, TRUE, TRUE, 1);
	gtk_box_pack_start (GTK_BOX (hbox), lbl, FALSE, TRUE, 1);

	gtk_box_pack_start (GTK_BOX (vbox), hbox, FALSE, TRUE, 1);

	hbox = gtk_hbox_new (FALSE, 1);
	gtk_box_pack_start (GTK_BOX (hbox), handle_nav, FALSE, TRUE, 1);
	gtk_box_pack_start (GTK_BOX (hbox), scrollbox, TRUE, TRUE, 1);

	gtk_box_pack_start (GTK_BOX (vbox), hbox, TRUE, TRUE, 1);

	gtk_container_add (GTK_CONTAINER (win1), vbox);
	update_saveable (GRG_SAVE_INACTIVE);
	created = TRUE;

	if ((fdesc = get_pref_font_string ()) != NULL)
	{
		set_editor_font (fdesc);
		g_free (fdesc);
	}
	else
	{
		set_pref_font_string_from_editor ();
	}

	update ();

	started = TRUE;
	gtk_widget_show_all (win1);
	if (grg_prefs_splash)
		gtk_widget_show_all (grg_splash (win1));
}

/**
 * main:
 * @argc: No need to tell... ;)
 * @argv: No need to tell... ;)
 *
 * No need to tell... ;)
 *
 * Returns: No need to tell... ;)
 */
gint
main (gint argc, gchar ** argv)
{
	gchar *file2load = NULL, *file2loadInArgv = NULL, *finalfile = NULL;
	guchar *version = grg_get_version (); /* libgringotts version */
	gint prefs_err;
	gboolean root = FALSE;

	if (!grg_mlockall_and_drop_root_privileges ())
		exit (1);

	gctx = grg_context_initialize_defaults ((guchar*)"GRG");

	/*parse cmdline args */
	grg_parse_argv (argc, argv, &file2loadInArgv, &root);

	if (!grg_security_filter (root))
	{
		grg_context_free (gctx);
		exit (1);
	}

	grg_recent_dox_init ();
	prefs_err = grg_load_prefs ();

	setlocale (LC_ALL, "");
	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	g_print ("\n" GRG_CAP_NAME " %s " GRG_VERSION
		 " (libGringotts %s)\n%s 2002 Germano Rizzo <mano78@users.sourceforge.net>\n\n%s\n%s\n",
		 _("version"), version, _("(c)"),
		 _
		 ("released under GNU General Public License (GPL) v.2 or later"),
		 _
		 ("See COPYING or go to http://www.gnu.org/copyleft/gpl.html"));
	g_free (version);

	gtk_init (&argc, &argv);

	entries_vis_init ();

	grg_interface ();

	/*if the preferences file is invalid, saves a default */
	if (prefs_err < 0)
	{
		g_warning ("%s",
			   _
			   ("Invalid preferences file. Resetting to defaults."));
		grg_prefs_reset_defaults ();
		grg_save_prefs ();
	}

	/*loads (ev.) a startup file */
	file2load = get_pref_file ();

	if (file2loadInArgv)
		finalfile = file2loadInArgv;

	if (file2load && !finalfile)
	{
		finalfile =
			g_filename_from_utf8 (file2load, -1, NULL, NULL,
					      NULL);
		g_free (file2load);
	}

	if (finalfile)
	{
		if (g_file_test (finalfile, G_FILE_TEST_IS_REGULAR))
			load_file (finalfile);
		else
			g_warning ("%s",
				   _
				   ("File to load does not exists or it is invalid"));
		g_free (finalfile);
	}

	gtk_loop_started = TRUE;
	gtk_main ();

	return 0;
}
