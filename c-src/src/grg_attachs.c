/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_attachs.c - functions to manage attachments
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
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <gtk/gtk.h>
#include <libgringotts.h>

#include "grg_defs.h"
#include "grg_entries.h"
#include "gringotts.h"
#include "grg_widgets.h"
#include "grg_safe.h"
#include "grg_attachs.h"

gint current_attach_ID;

#ifdef ATTACH_LIMIT
#define ATT_SIZE_MAX 2057152
static guint total_size = 0;
#endif

gint
grg_attach_file (gchar * path, GtkWidget * parent)
{
	GtkWidget *wait;
	GList *ceal = ((struct grg_entry *) current->data)->attach;	/*Current Entry Attachment List*/
	struct grg_attachment *newatt;
	gint fd, ID;
	glong fdim;
	gchar *comment;
	void *data;
	struct stat info;

	if (!ceal)
		ID = 0;
	else
		ID = ((struct grg_attachment *) (g_list_last (ceal))->data)->
			ID + 1;

	fd = grg_safe_open (path);

	if (fd < 3)
	{
		grg_msg (_("Cannot open file to attach."), GTK_MESSAGE_ERROR,
			 parent);
		return -1;
	}

	if (fd == GRG_OPEN_FILE_IRREGULAR)
	{
		grg_msg (_("Only regular files can be attached."),
			 GTK_MESSAGE_ERROR, parent);
		return -1;
	}

	fstat (fd, &info);
	fdim = info.st_size;

#ifdef ATTACH_LIMIT
	if (total_size + fdim > ATT_SIZE_MAX)
	{
		grg_msg (_
			 ("Sorry, currently you can attach files only up to 2 Mb"),
			 GTK_MESSAGE_ERROR, parent);
		close (fd);
		return -1;
	}
#endif

	comment =
		grg_input_dialog (_("Enter comment"),
				  _
				  ("Please enter a comment for this\nfile (max. 32 chars)"),
				  "", FALSE, parent);

	if (!comment)
	{
		close (fd);
		return -1;
	}

	if (STR_EQ (comment, ""))
		comment = g_strdup (_("none"));

	newatt = (struct grg_attachment *)
		grg_malloc (sizeof (struct grg_attachment));
	newatt->ID = ID;
	newatt->filedim = fdim;
	newatt->filename = g_path_get_basename (path);
	newatt->comment = comment;
	newatt->pointer = grg_tmpfile_gen (gctx);

	wait = grg_wait_msg (_("attaching"), parent);

	data = mmap (NULL, newatt->filedim, PROT_READ, MAP_PRIVATE, fd, 0);

	if (grg_tmpfile_write (gctx, newatt->pointer, data, newatt->filedim) <
	    0)
	{
		gtk_widget_destroy (wait);
		grg_msg (_("Cannot encode tempfile."), GTK_MESSAGE_ERROR,
			 parent);
		munmap (data, newatt->filedim);
		close (fd);
		GRGFREE (newatt, sizeof (struct grg_attachment));
		return -1;
	}

	munmap (data, newatt->filedim);
	close (fd);

	gtk_widget_destroy (wait);

	((struct grg_entry *) current->data)->attach =
		g_list_append (ceal, newatt);

#ifdef ATTACH_LIMIT
	total_size += fdim;
#endif

	return ID;
}

gint
grg_attach_content (void *cont, glong fdim, gchar * fname, gchar * comment)
{
	GList *ceal = ((struct grg_entry *) current->data)->attach;
	struct grg_attachment *newatt;
	gint ID;

	if (!ceal)
		ID = 0;
	else
		ID = ((struct grg_attachment *) (g_list_last (ceal))->data)->
			ID + 1;

	newatt = (struct grg_attachment *)
		grg_malloc (sizeof (struct grg_attachment));
	newatt->ID = ID;
	newatt->filedim = fdim;
	newatt->filename = g_strdup (fname);
	newatt->comment = g_strdup (comment);
	newatt->pointer = grg_tmpfile_gen (gctx);

	if (grg_tmpfile_write (gctx, newatt->pointer, cont, newatt->filedim) <
	    0)
	{
		GRGFREE (newatt, sizeof (struct grg_attachment));
		return -1;
	}

	((struct grg_entry *) current->data)->attach =
		g_list_append (ceal, newatt);

#ifdef ATTACH_LIMIT
	total_size += fdim;
#endif

	return ID;
}

gint
grg_get_content (struct grg_attachment * att, void **cont, GtkWidget * parent)
{
	GRG_TMPFILE tmpf = att->pointer;

	if (grg_tmpfile_read (gctx, tmpf, (unsigned char **) cont, NULL) < 0)
	{
		if (parent)
			grg_msg (_("Cannot decode tempfile."),
				 GTK_MESSAGE_ERROR, parent);
		return FALSE;
	}

	return TRUE;
}

void
grg_attachment_free (gpointer att, gpointer user_data)
{
	GRGAFREE (((struct grg_attachment *) att)->filename);
	GRGAFREE (((struct grg_attachment *) att)->comment);
	grg_tmpfile_close (gctx, ((struct grg_attachment *) att)->pointer);
	GRGFREE (att, sizeof (struct grg_attachment));
}

void
grg_remove_attachment (void)
{
	GList *tmp = ((struct grg_entry *) current->data)->attach;

	while (tmp
	       && ((struct grg_attachment *) tmp->data)->ID !=
	       current_attach_ID)
		tmp = tmp->next;

	if (!tmp)
		return;

	((struct grg_entry *) current->data)->attach =
		g_list_remove_link (((struct grg_entry *) current->data)->
				    attach, tmp);

#ifdef ATTACH_LIMIT
	total_size -= ((struct grg_attachment *) tmp->data)->filedim;
#endif
	grg_attachment_free ((struct grg_attachment *) tmp->data, NULL);
	g_list_free_1 (tmp);

	return;
}

void
grg_attach_list_free (GList * ceal)
{
	g_list_foreach (ceal, grg_attachment_free, NULL);
	g_list_free (ceal);
	current_attach_ID = -1;
#ifdef ATTACH_LIMIT
	total_size = 0;
#endif
}

gboolean
grg_save_attachment (gchar * path, GtkWidget * parent)
{
	GtkWidget *wait;
	GList *tmp = ((struct grg_entry *) current->data)->attach;
	GRG_TMPFILE tmpf;
	guchar *mem;
	gint fd;
	glong memDim;

	while (tmp
	       && ((struct grg_attachment *) tmp->data)->ID !=
	       current_attach_ID)
		tmp = tmp->next;

	if (!tmp)
		return FALSE;

	tmpf = ((struct grg_attachment *) tmp->data)->pointer;

	wait = grg_wait_msg (_("saving"), parent);

	if (grg_tmpfile_read (gctx, tmpf, &mem, &memDim) < 0)
	{
		gtk_widget_destroy (wait);
		grg_msg (_("Cannot decode tempfile."), GTK_MESSAGE_ERROR,
			 parent);
		return FALSE;
	}

	fd = open (path, O_WRONLY | O_CREAT | O_EXCL,
		   S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR);

	if (fd < 3)
	{
		gtk_widget_destroy (wait);
		grg_msg (_("Cannot create file, or file already existent."),
			 GTK_MESSAGE_ERROR, parent);
		GRGFREE (mem, memDim);
		close (fd);
		return FALSE;
	}

	write (fd, mem, memDim);
	GRGFREE (mem, memDim);
	close (fd);
	gtk_widget_destroy (wait);
	return TRUE;
}

void
grg_info_attachment (GtkWidget * parent)
{
	GList *tmp = ((struct grg_entry *) current->data)->attach;
	struct grg_attachment *att;
	gchar *msg;

	while (tmp
	       && ((struct grg_attachment *) tmp->data)->ID !=
	       current_attach_ID)
		tmp = tmp->next;

	if (!tmp)
		return;

	att = (struct grg_attachment *) tmp->data;

	msg = g_strdup_printf ("%s:\n  %s\n\n%s:\n  %ld %s\n\n%s:\n  %s",
			       _("File name"), att->filename,
			       _("Dimension"), att->filedim, _("bytes"),
			       _("Comment"), att->comment);
	grg_msg (msg, GTK_MESSAGE_INFO, parent);
	GRGAFREE (msg);
}

/*true if the action gets performed*/
gboolean
grg_attachment_change_comment (GtkWidget * parent)
{
	GList *tmp = ((struct grg_entry *) current->data)->attach;
	struct grg_attachment *att;
	gchar *comment;

	while (tmp && ((struct grg_attachment*) tmp->data)->ID != current_attach_ID)
		tmp = tmp->next;

	if (!tmp)
		return FALSE;

	att = (struct grg_attachment *) tmp->data;

	comment = grg_input_dialog (_("Enter comment"),
		_("Please enter a comment for this\nfile (max. 32 chars)"),
		att->comment, FALSE, parent);

	if (!comment)
		return FALSE;

	if (STR_EQ (comment, ""))
		comment = g_strdup (_("none"));

	GRGAFREE (att->comment);
	att->comment = comment;

	return TRUE;
}

static void
set_ID (gpointer ignore, gpointer void_combo_attach)
{
    GtkComboBox * combo_attach;
    GtkTreeIter iter;

    combo_attach = (GtkComboBox *)void_combo_attach;

    if (gtk_combo_box_get_active_iter (combo_attach, &iter))
    {
        GValue value = { 0, };
        
        gtk_tree_model_get_value (gtk_combo_box_get_model (combo_attach),
                &iter, ATTACHMENT_ID, &value);
        current_attach_ID = g_value_get_int (&value);
    }
}

static gchar *
gen_index_string (const gchar * fname, const glong dim)
{
	gchar *nfn, *u, *fmt, *ret;
	gfloat fdim = dim;

	if (strlen (fname) > 10)
		nfn = g_strdup_printf ("%.10s...", fname);
	else
		nfn = g_strdup (fname);

	if (fdim < 1024)
	{
		u = _("bytes");
		fmt = "%s (%.0f %s)";
	}
	else
	{
		fdim /= 1024;
		if (fdim < 1024)
		{
			u = _("Kb");
			fmt = "%s (%.0f %s)";
		}
		else
		{
			fdim /= 1024;
			u = _("Mb");
			fmt = "%s (%.2f %s)";
		}
	}

	ret = g_strdup_printf (fmt, nfn, fdim, u);

	GRGAFREE (nfn);

	return ret;
}

void
grg_attachment_fill_combo_box (GtkComboBox * combo_attach)
{
    GList *ceal;

    if (current)
        ceal = ((struct grg_entry *) current->data)->attach;
    else
        ceal = NULL;

    if (!ceal)
    {
        GtkTreeIter iter;
        GtkTreeModel *model;

        model = gtk_combo_box_get_model(combo_attach);
        gtk_list_store_clear (GTK_LIST_STORE (model));
        
        gtk_list_store_append (GTK_LIST_STORE (model), &iter);
        gtk_list_store_set (GTK_LIST_STORE (model), &iter,
                ATTACHMENT_TITLE, _("<no file attached>"),
                ATTACHMENT_ID, (-1),
                -1
                );
        gtk_combo_box_set_active_iter (combo_attach, &iter);
        gtk_widget_set_sensitive (GTK_WIDGET (combo_attach), FALSE);
        current_attach_ID = -1;
    }
    else
    {
        GtkTreeIter iter;
        GtkTreeModel *model;
        model = gtk_combo_box_get_model(combo_attach);
        gtk_list_store_clear (GTK_LIST_STORE (model));
        
        current_attach_ID =
            ((struct grg_attachment *) ceal->data)->ID;
        while (ceal)
        {
            struct grg_attachment *att =
                (struct grg_attachment *) ceal->data;
            gchar *lbl;

            lbl = gen_index_string (att->filename, att->filedim);

            gtk_list_store_append (GTK_LIST_STORE (model), &iter);
            gtk_list_store_set (GTK_LIST_STORE (model), &iter,
                ATTACHMENT_TITLE, lbl,
                ATTACHMENT_ID, (att->ID),
                -1
                );

            GRGAFREE (lbl);

            ceal = ceal->next;
        }
        g_signal_connect (G_OBJECT (combo_attach), "changed",
                          G_CALLBACK (set_ID),
                          (gpointer)combo_attach);

        gtk_widget_set_sensitive (GTK_WIDGET (combo_attach), TRUE);
    }
}

