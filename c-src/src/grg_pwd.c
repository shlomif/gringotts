/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_pwd.c - widgets used to get passwords
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <langinfo.h>

#include <gtk/gtk.h>

#include "grg_defs.h"
#include "grg_pwd.h"
#include "grg_widgets.h"
#include "grg_popt.h"
#include "grg_safe.h"
#include "gringotts.h"

#if defined(BLOCK_DEV_IS_FLOPPY) && defined(HAVE_LINUX_FD_H)
#include <linux/fd.h>
#endif

#define TYPE_PWD	0
#define TYPE_FILE	1
#define TYPE_DISK	2

#define NEW_RADIO_BUTTON(widget, list, call, value, label, box) \
	widget = gtk_radio_button_new_with_label(list, label); \
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (call), GINT_TO_POINTER(value)); \
	gtk_box_pack_start(GTK_BOX(box), widget, FALSE, FALSE, GRG_PAD);

#define NEW_LABEL(box, text) \
	{ \
		GtkWidget *new_lbl; \
		new_lbl = gtk_label_new(text); \
		gtk_misc_set_alignment(GTK_MISC(new_lbl), 0, 0); \
		gtk_box_pack_start(GTK_BOX(box), new_lbl, FALSE, FALSE, GRG_PAD); \
	}

#define SWAP_BUTTONS(widget, stock, block, unblock) \
	gtk_button_set_label (GTK_BUTTON(widget), stock); \
	g_signal_handler_block (widget, block); \
	g_signal_handler_unblock (widget, unblock);

#define NEW_SEPARATOR(box) \
	gtk_box_pack_start (GTK_BOX (box), gtk_hseparator_new (), FALSE, FALSE, GRG_PAD);

static void
meta_browse (GtkWidget * data, GtkWidget * entry)
{
    GtkWidget *file_chooser;
	gint response;

	GtkWidget *dlg =
        gtk_widget_get_parent(
            gtk_widget_get_parent(
                gtk_widget_get_parent(
                    data
                )
            )
        );

    file_chooser = gtk_file_chooser_dialog_new (_("Open..."),
            GTK_WINDOW (dlg),
            GTK_FILE_CHOOSER_ACTION_OPEN,
            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
            GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
            NULL);

	response = gtk_dialog_run (GTK_DIALOG (file_chooser));
    if (response == GTK_RESPONSE_ACCEPT)
	{
        gchar *filename;

        filename = gtk_file_chooser_get_filename (
                GTK_FILE_CHOOSER (file_chooser)
                );

		gchar *ufile =
			g_filename_to_utf8 (filename, -1, NULL, NULL,
					    NULL);
        g_free(filename);
		gtk_entry_set_text (GTK_ENTRY (entry), ufile);
		g_free (ufile);
	}
    gtk_widget_destroy (file_chooser);
}

static GRG_KEY
read_pwd_file (const gchar * path, GtkWidget * dlg, gboolean X)
{
	GtkWidget *wait = NULL;
	gint fd, len;
	gchar *upath;
    guchar *pwd;
	GRG_KEY key;
	struct stat buf;

	upath = g_filename_from_utf8 (path, -1, NULL, NULL, NULL);
	fd = grg_safe_open (upath);
	g_free (upath);

	if (fd < 3)
	{
		report_err (_("The file does not exist"), X, 0, dlg);
		return NULL;
	}

	if (fd == GRG_OPEN_FILE_IRREGULAR)
	{
		report_err (_("You must specify a regular file"), X, 0, dlg);
		close (fd);
		return NULL;
	}

	fstat (fd, &buf);
	len = buf.st_size;

	if (X)
		wait = grg_wait_msg (_("reading file"), dlg);

	pwd = mmap (NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
	key = grg_key_gen (pwd, len);
	munmap (pwd, len);
	close (fd);

	if (X)
		gtk_widget_destroy (wait);

	return key;
}

static GRG_KEY
read_pwd_disk (GtkWidget * dlg, gboolean X)
{
	GtkWidget *wait = NULL;
	gint fd, len;
	guchar *file;
	GRG_KEY key = NULL;

#if defined(BLOCK_DEV_IS_FLOPPY) && defined(HAVE_LINUX_FD_H)
	struct floppy_drive_struct fstruct;
#endif

	fd = open (BLOCK_DEV, O_RDONLY);

	/*check 4 disk presence*/
	if (fd < 0)
	{
		report_err (_
			    ("Please insert a disk in the first floppy drive"),
			    X, 0, dlg);
		return NULL;
	}

#if defined(BLOCK_DEV_IS_FLOPPY) && defined(HAVE_LINUX_FD_H)
	/*check for write protection*/
	ioctl (fd, FDGETDRVSTAT, &fstruct);

	if ((fstruct.flags >> FD_DISK_WRITABLE_BIT) & 1)
	{
		report_err (_
			    ("The disk is not write protected. For security reasons, I'll not use it."),
			    X, 0, dlg);
		close (fd);
		return NULL;
	}
#endif

	len = lseek (fd, 0, SEEK_END);

	if (X)
		wait = grg_wait_msg (_("reading floppy"), dlg);

	file = mmap (NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
	key = grg_key_gen (file, len);
	munmap (file, len);
	close (fd);

	if (X)
		gtk_widget_destroy (wait);

	return key;
}

/*******************
* CHANGE PWD DIALOG *
 *******************/
static GtkWidget *label, *hbox_file, *vbox_pwd;
static GtkWidget *file_entry, *question, *question2, *quality;
static int curr_type_pwd_chg = TYPE_PWD;

static void
toggle_pwd_chg_file (GtkWidget * data, gpointer value)
{
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data)))
		return;

	curr_type_pwd_chg = GPOINTER_TO_INT (value);

	switch (curr_type_pwd_chg)
	{
	case TYPE_PWD:
		gtk_label_set_text (GTK_LABEL (label),
				    _("Enter new password"));
		gtk_entry_set_text (GTK_ENTRY (question), "");
		gtk_entry_set_text (GTK_ENTRY (question2), "");
		gtk_widget_hide (hbox_file);
		gtk_widget_show_all (vbox_pwd);
		gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (quality), 0);
		break;
	case TYPE_FILE:
		gtk_label_set_text (GTK_LABEL (label), _("Choose file"));
		gtk_entry_set_text (GTK_ENTRY (file_entry), "");
		gtk_widget_hide (vbox_pwd);
		gtk_widget_show_all (hbox_file);
		gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (quality), 0);
		break;
	case TYPE_DISK:
		gtk_label_set_text (GTK_LABEL (label),
				    _("Insert a disk and press Ok"));
		gtk_widget_hide (vbox_pwd);
		gtk_widget_hide (hbox_file);
		gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (quality), 1);
		break;
	}

	return;
}

static void
vis_quality (gpointer ignore, gpointer type)
{
	switch (GPOINTER_TO_INT (type))
	{
	case TYPE_PWD:
	{
		gsize bout;
		gchar *sq = NULL;

		if (!mapIsUTF)
			sq = g_locale_from_utf8 (gtk_entry_get_text
						 (GTK_ENTRY (question)), -1,
						 NULL, &bout, NULL);

		gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (quality),
					       grg_ascii_pwd_quality ((guchar*)(mapIsUTF
								      ?
								      gtk_entry_get_text
								      (GTK_ENTRY
								       (question))
								      : sq),
								      g_utf8_strlen
								      (gtk_entry_get_text
								       (GTK_ENTRY
									(question)),
								       -1)));

		if (!mapIsUTF)
			GRGFREE (sq, bout);
	}
		break;
	case TYPE_FILE:
	{
		gchar *upath =
			g_filename_from_utf8 (
					      gtk_entry_get_text (GTK_ENTRY
								  (file_entry)),
					      -1, NULL, NULL, NULL);
		gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (quality),
					       grg_file_pwd_quality ((guchar*)upath));
		g_free (upath);
	}
		break;
	case TYPE_DISK:
		gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (quality), 1);
		break;
	}
}

/**
 * grg_new_pwd_dialog:
 * @parent: the parent of the dialog to create.
 *
 * Asks for a new password, validating it (>4 chars).
 *
 * Returns: the new password, or NULL if user Cancel-ed
 */
GRG_KEY
grg_new_pwd_dialog (GtkWidget * parent, gboolean * cancelled)
{
	GtkWidget *dialog, *label2;
	GtkWidget *chk_file, *chk_pwd, *chk_disk;
	GtkWidget *browse;
	GRG_KEY key = NULL;

	curr_type_pwd_chg = TYPE_PWD;

	dialog = gtk_dialog_new_with_buttons (_("New password"),
					      GTK_WINDOW (parent),
					      GTK_DIALOG_MODAL |
					      GTK_DIALOG_DESTROY_WITH_PARENT,
					      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					      GTK_STOCK_OK, GTK_RESPONSE_OK,
						  NULL);

	gtk_dialog_set_default_response (GTK_DIALOG (dialog),
					 GTK_RESPONSE_OK);
	gtk_container_set_border_width (GTK_CONTAINER (dialog), 3);
	gtk_box_set_spacing (GTK_BOX (gtk_dialog_get_content_area(GTK_DIALOG(dialog))), 3);
	gtk_window_set_resizable (GTK_WINDOW (dialog), FALSE);

	NEW_LABEL (gtk_dialog_get_content_area(GTK_DIALOG(dialog)), _("Choose password type:"));

	NEW_RADIO_BUTTON (chk_pwd, NULL, toggle_pwd_chg_file, TYPE_PWD,
			  _("String"), gtk_dialog_get_content_area(GTK_DIALOG(dialog)));
	NEW_RADIO_BUTTON (chk_file,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (chk_pwd)),
			  toggle_pwd_chg_file, TYPE_FILE, _("File"),
			  gtk_dialog_get_content_area(GTK_DIALOG(dialog)));
	NEW_RADIO_BUTTON (chk_disk,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (chk_pwd)),
			  toggle_pwd_chg_file, TYPE_DISK, _("Disk"),
			  gtk_dialog_get_content_area(GTK_DIALOG(dialog)));

	NEW_SEPARATOR (gtk_dialog_get_content_area(GTK_DIALOG(dialog)));

	label = gtk_label_new (_("Enter new password:"));
	pack_start_defaults (GTK_BOX (gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
				     label);

	vbox_pwd = gtk_vbox_new (FALSE, GRG_PAD);
	pack_start_defaults (GTK_BOX (gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
				     vbox_pwd);

	label2 = gtk_label_new (_("Enter it again for confirmation:"));

	question = gtk_entry_new ();
	g_signal_connect (G_OBJECT (question), "key-press-event",
			  G_CALLBACK (return_submit), (gpointer) dialog);
	gtk_entry_set_visibility (GTK_ENTRY (question), FALSE);
	g_signal_connect (G_OBJECT (question), "changed",
			  G_CALLBACK (vis_quality),
			  GINT_TO_POINTER (TYPE_PWD));

	question2 = gtk_entry_new ();
	g_signal_connect (G_OBJECT (question2), "key-press-event",
			  G_CALLBACK (return_submit), (gpointer) dialog);
	gtk_entry_set_visibility (GTK_ENTRY (question2), FALSE);

	pack_start_defaults (GTK_BOX (vbox_pwd), question);
	pack_start_defaults (GTK_BOX (vbox_pwd), label2);
	pack_start_defaults (GTK_BOX (vbox_pwd), question2);

	hbox_file = gtk_hbox_new (FALSE, GRG_PAD);

	file_entry = gtk_entry_new ();
	g_signal_connect (G_OBJECT (file_entry), "key-press-event",
			  G_CALLBACK (return_submit), (gpointer) dialog);
	g_signal_connect (G_OBJECT (file_entry), "changed",
			  G_CALLBACK (vis_quality),
			  GINT_TO_POINTER (TYPE_FILE));
	browse = gtk_button_new_from_stock (GTK_STOCK_OPEN);
	g_signal_connect (G_OBJECT (browse), "clicked",
			  G_CALLBACK (meta_browse), (gpointer) file_entry);
	pack_start_defaults (GTK_BOX (hbox_file), file_entry);
	pack_start_defaults (GTK_BOX (hbox_file), browse);

	NEW_SEPARATOR (gtk_dialog_get_content_area(GTK_DIALOG(dialog)));

	quality = gtk_progress_bar_new ();
	gtk_progress_bar_set_text (GTK_PROGRESS_BAR (quality),
				   _("password quality"));
	gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (quality), 0.0);

	pack_start_defaults (GTK_BOX (gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
				     quality);

	/*show all...*/
	gtk_widget_grab_focus (question);
	gtk_widget_show_all (gtk_dialog_get_content_area(GTK_DIALOG(dialog)));
	/*...but the file selection part*/
	pack_start_defaults (GTK_BOX (gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
				     hbox_file);
	gtk_box_reorder_child (GTK_BOX (gtk_dialog_get_content_area(GTK_DIALOG(dialog))), hbox_file,
			       7);

	while (TRUE)
	{
		gint res = gtk_dialog_run (GTK_DIALOG (dialog));
		gboolean exit = FALSE;
		grg_key_free (gctx, key);
		key = NULL;

		if (res != GTK_RESPONSE_OK)
		{
			if (cancelled)
				*cancelled = TRUE;
			break;
		}

		switch (curr_type_pwd_chg)
		{
		case TYPE_PWD:
		{
			gchar *ret1 =
				g_strdup(
					gtk_entry_get_text (GTK_ENTRY (question))
				);
			gchar *ret2 =
				g_strdup(
					gtk_entry_get_text (GTK_ENTRY (question2))
				);
			grg_trim_password_trailing_newlines(ret1);
			grg_trim_password_trailing_newlines(ret2);
			gint pwd_len = strlen (ret1);

			if (g_utf8_strlen (ret1, -1) < 4)
			{
				report_err (_
					    ("The password is too short, it must be at least 4 chars"),
					    1, 0, dialog);
				gtk_entry_set_text (GTK_ENTRY (question), "");
				gtk_entry_set_text (GTK_ENTRY (question2),
						    "");

				goto pwd_release;
			}

			if (!STR_EQ (ret1, ret2))
			{
				report_err (_
					    ("The two passwords are different"),
					    1, 0, dialog);
				gtk_entry_set_text (GTK_ENTRY (question), "");
				gtk_entry_set_text (GTK_ENTRY (question2),
						    "");

				goto pwd_release;
			}

			key = grg_key_gen ((guchar*)ret1, pwd_len);

			exit = TRUE;
pwd_release:
			g_free(ret1);
			g_free(ret2);
			break;
		}
		case TYPE_FILE:
		{
			const gchar *path =
				gtk_entry_get_text (GTK_ENTRY (file_entry));

			key = read_pwd_file (path, dialog, TRUE);
			if (key)
				exit = TRUE;

			break;
		}
		case TYPE_DISK:
		{
			key = read_pwd_disk (dialog, TRUE);
			if (key)
				exit = TRUE;

			break;
		}
		}
		if (exit)
			break;
	}

	gtk_widget_destroy (dialog);

	return key;
}

/****************
* ASK PWD DIALOG *
 ****************/
static GtkWidget *util_button, *entry, *hbox, *dlabel;
static guint sigclear, sigbrowse, curr_type_pwd_req = TYPE_PWD;
static gboolean sigbrowse_blocked;

static void
clear_entry (GtkWidget * data, GtkWidget * dentry)
{
	gtk_entry_set_text (GTK_ENTRY (dentry), "");
}

static void
toggle_pwd_file (GtkWidget * data, gpointer value)
{
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data)))
		return;

	curr_type_pwd_req = GPOINTER_TO_INT (value);

	switch (curr_type_pwd_req)
	{
	case TYPE_PWD:
	{
		if (!sigbrowse_blocked)
		{
			SWAP_BUTTONS (util_button, GTK_STOCK_CLEAR, sigbrowse,
				      sigclear);
			sigbrowse_blocked = TRUE;
		}
		gtk_entry_set_text (GTK_ENTRY (entry), "");
		gtk_entry_set_visibility (GTK_ENTRY (entry), FALSE);
		gtk_widget_hide (dlabel);
		gtk_widget_show_all (hbox);
	}
		break;
	case TYPE_FILE:
	{
		if (sigbrowse_blocked)
		{
			SWAP_BUTTONS (util_button, GTK_STOCK_OPEN, sigclear,
				      sigbrowse);
			sigbrowse_blocked = FALSE;
		}
		gtk_entry_set_text (GTK_ENTRY (entry), "");
		gtk_entry_set_visibility (GTK_ENTRY (entry), TRUE);
		gtk_widget_show_all (hbox);
		gtk_widget_hide (dlabel);
	}
		break;
	case TYPE_DISK:
	{
		gtk_widget_hide (hbox);
		gtk_widget_show (dlabel);
	}
		break;
	}
}

GRG_KEY
grg_ask_pwd_dialog (GtkWidget * parent, gboolean * cancelled)
{
	GtkWidget *dlg;
	GtkWidget *chk_file, *chk_pwd, *chk_disk;
	GRG_KEY key = NULL;

	curr_type_pwd_req = TYPE_PWD;

	dlg = gtk_dialog_new_with_buttons (_("Enter password"),
					   GTK_WINDOW (parent),
					   GTK_DIALOG_MODAL |
					   GTK_DIALOG_DESTROY_WITH_PARENT,
					   GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					   GTK_STOCK_OK, GTK_RESPONSE_OK,
					   NULL);
	gtk_dialog_set_default_response (GTK_DIALOG (dlg),
					 GTK_RESPONSE_CANCEL);
	gtk_container_set_border_width (GTK_CONTAINER (dlg), 3);
	gtk_box_set_spacing (GTK_BOX (gtk_dialog_get_content_area(GTK_DIALOG(dlg))), 3);
	gtk_window_set_resizable (GTK_WINDOW (dlg), FALSE);

	NEW_LABEL (gtk_dialog_get_content_area(GTK_DIALOG(dlg)), _("Choose password type:"));
	NEW_RADIO_BUTTON (chk_pwd, NULL, toggle_pwd_file, TYPE_PWD,
			  _("String"), gtk_dialog_get_content_area(GTK_DIALOG(dlg)));
	NEW_RADIO_BUTTON (chk_file,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (chk_pwd)),
			  toggle_pwd_file, TYPE_FILE, _("File"),
			  gtk_dialog_get_content_area(GTK_DIALOG(dlg)));
	NEW_RADIO_BUTTON (chk_disk,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (chk_pwd)),
			  toggle_pwd_file, TYPE_DISK, _("Disk"),
			  gtk_dialog_get_content_area(GTK_DIALOG(dlg)));
	NEW_SEPARATOR (gtk_dialog_get_content_area(GTK_DIALOG(dlg)));

	hbox = gtk_hbox_new (FALSE, GRG_PAD);
	entry = gtk_entry_new ();
	gtk_entry_set_visibility (GTK_ENTRY (entry), FALSE);
	g_signal_connect (G_OBJECT (entry), "key-press-event",
			  G_CALLBACK (return_submit), (gpointer) dlg);
	gtk_box_pack_start (GTK_BOX (hbox), entry, FALSE, FALSE, 0);
	util_button = gtk_button_new_from_stock (GTK_STOCK_CLEAR);
	gtk_button_set_use_stock (GTK_BUTTON (util_button), TRUE);
	sigclear =
		g_signal_connect (G_OBJECT (util_button), "clicked",
				  G_CALLBACK (clear_entry), (gpointer) entry);
	sigbrowse =
		g_signal_connect (G_OBJECT (util_button), "clicked",
				  G_CALLBACK (meta_browse), (gpointer) entry);
	g_signal_handler_block (util_button, sigbrowse);
	sigbrowse_blocked = TRUE;
	gtk_box_pack_start (GTK_BOX (hbox), util_button, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (gtk_dialog_get_content_area(GTK_DIALOG(dlg))), hbox, FALSE,
			    FALSE, 0);

	dlabel = gtk_label_new (_("Insert a disk and press Ok"));
	gtk_box_pack_start (GTK_BOX (gtk_dialog_get_content_area(GTK_DIALOG(dlg))), dlabel, FALSE,
			    FALSE, 0);

	gtk_widget_grab_focus (entry);
	gtk_widget_show_all (dlg);
	gtk_widget_hide (dlabel);

	while (TRUE)
	{
		gboolean exit;
		gint response;
		clear_entry (NULL, entry);
		response = gtk_dialog_run (GTK_DIALOG (dlg));
		exit = FALSE;
		grg_key_free (gctx, key);
		key = NULL;

		if (response != GTK_RESPONSE_OK)
		{
			if (cancelled)
				*cancelled = TRUE;
			break;
		}

		switch (curr_type_pwd_req)
		{
		case TYPE_PWD:
		{
			gchar * password = g_strdup(gtk_entry_get_text (GTK_ENTRY (entry)));
			grg_trim_password_trailing_newlines(password);
			key = grg_key_gen ((guchar*)password, -1);
			g_free(password);
			exit = TRUE;
		}
		break;
		case TYPE_FILE:
		{
			const gchar *path =
				gtk_entry_get_text (GTK_ENTRY (entry));
			key = read_pwd_file (path, dlg, TRUE);

			if (key)
				exit = TRUE;

			break;
		}
		case TYPE_DISK:
			key = read_pwd_disk (dlg, TRUE);

			if (key)
				exit = TRUE;

			break;
		}

		if (exit)
			break;
	}

	gtk_widget_destroy (dlg);

	return key;
}

static gchar *
get_cmdln_string (gchar * prompt, gint max_len, gboolean hidden)
{
	gchar *answ = (gchar *) grg_malloc (max_len), *ret;
	gint i = 0;
	gchar c;

	fprintf (stderr, "%s: ", prompt);

	if (hidden)
		block_term ();

	c = getchar ();
	if (c != '\n' && c != '\r')
	{
		answ[i] = c;
		i++;
	}

	while (TRUE)
	{
		if (i >= max_len)
			break;
		c = getchar ();
		if (c == '\n' || c == '\r')
			break;
		answ[i] = c;
		i++;
	}

	if (hidden)
		unblock_term ();

	ret = g_strndup (answ, i);
	GRGFREE (answ, max_len);

	return ret;
}

GRG_KEY
grg_get_cmdline_key (void)
{
	gchar *prompt, *choice;
	GRG_KEY ret = NULL;

	prompt = g_strdup_printf
		("%s \n  0 - %s\n  1 - %s\n  2 - %s\n  3 - %s",
		 _("Choose password type:"), _("String"), _("File"),
		 _("Disk"), _("Quit"));
	fprintf (stderr, "%s\n", prompt);
	g_free (prompt);
	choice = get_cmdln_string (_("Choice"), 1, FALSE);
	fprintf (stderr, "\n");

	if (choice[0] < '0' || choice[0] > '3')
		choice[0] = '0';

	switch (choice[0])
	{
	case '0':
	{
		gchar *pwd;

		pwd = get_cmdln_string (_("Enter password"), 32, TRUE);
		if (!mapIsUTF)
		{
			gchar *UTF8d;
			gsize ulen;

			UTF8d = g_locale_to_utf8 (pwd, -1, NULL, &ulen, NULL);
			ret = grg_key_gen ((guchar*)UTF8d, ulen);
			GRGFREE (UTF8d, ulen);
			ulen = 0;
		}
		else
			ret = grg_key_gen ((guchar*)pwd, -1);
		GRGAFREE (pwd);
	}
		break;
	case '1':
	{
		gchar *pwd = get_cmdln_string (_("Choose file"), 256, TRUE);
		if (!mapIsUTF)
		{
			gchar *UTF8d;
			gsize ulen;

			UTF8d = g_locale_to_utf8 (pwd, -1, NULL, &ulen, NULL);
			ret = read_pwd_file (UTF8d, NULL, FALSE);
			GRGFREE (UTF8d, ulen);
			ulen = 0;
		}
		else
			ret = read_pwd_file (pwd, NULL, FALSE);
		GRGAFREE (pwd);
	}
		break;
	case '2':
		ret = read_pwd_disk (NULL, FALSE);
		break;
	case '3':
		printf ("%s :)\n", _("Bye, then!"));
		quit (0);
		break;
	}
	fprintf (stderr, "\n");

	g_free (choice);
	return ret;
}
