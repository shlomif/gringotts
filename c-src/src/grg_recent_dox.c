/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_recent_dox.c - manages the recently-opened-docs list
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

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <glib.h>

#include "grg_recent_dox.h"
#include "grg_menus.h"
#include "grg_defs.h"
#include "grg_safe.h"

GSList *grg_recent_dox = NULL;

static void
gather_paths (GMarkupParseContext * context, const gchar * text,
	      gsize text_len, gpointer user_data, GError ** error)
{
	gchar *sfile = g_strstrip (g_strndup (text, text_len));
	gchar *ufile = g_filename_from_utf8 (sfile, -1, NULL, NULL, NULL);
	g_free (sfile);

	if ((g_file_test (ufile, G_FILE_TEST_IS_REGULAR)) &&
	    (g_slist_length (grg_recent_dox) < GRG_RECENT_LIMIT))
		grg_recent_dox = g_slist_append (grg_recent_dox, ufile);
	else
		g_free (ufile);
}

void
grg_recent_dox_init (void)
{
	gchar *path, *content;
	int fd, end;
	GMarkupParser *context =
		(GMarkupParser *) grg_malloc (sizeof (GMarkupParser));
	GMarkupParseContext *parser;
	GError *err = NULL;

	path = g_build_filename (g_get_home_dir (), ".gringotts.recent",
				 NULL);
	fd = open (path, O_RDONLY);
	g_free (path);

	if (fd < 3)
	{
		close (fd);
		return;
	}

	end = lseek (fd, 0, SEEK_END);
	lseek (fd, 0, SEEK_SET);

	context->start_element = NULL;
	context->end_element = NULL;
	context->text = gather_paths;
	context->passthrough = NULL;
	context->error = NULL;

	parser = g_markup_parse_context_new (context, 0, NULL, NULL);

	content = (gchar *) mmap (NULL, end, PROT_READ, MAP_PRIVATE, fd, 0);

	g_markup_parse_context_parse (parser, content, end, &err);
	if (!err)
		g_markup_parse_context_end_parse (parser, &err);

	g_markup_parse_context_free (parser);
	if (err)
		g_error_free (err);
	g_free (context);

	munmap (content, end);
	close (fd);
}

void
grg_recent_dox_deinit (void)
{
	g_slist_foreach (grg_recent_dox, (GFunc) g_free, NULL);
	g_slist_free (grg_recent_dox);
}

static void
recent_dox_save (void)
{
	gchar *path, i = 1;
	GSList *cur;
	gint fd;

	path = g_build_filename (g_get_home_dir (), ".gringotts.recent",
				 NULL);
	fd = open (path, O_WRONLY | O_CREAT | O_TRUNC,
		   S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR);
	g_free (path);

	if (fd < 3)
	{
		close (fd);
		return;
	}

	cur = grg_recent_dox;

	while (cur && (i <= GRG_RECENT_LIMIT))
	{
		gchar *row, *urow;
		row = g_strdup_printf ("<file pos=\"%d\">\n%s\n</file>\n", i,
				       (guchar *) cur->data);
		urow = g_locale_to_utf8 (row, -1, NULL, NULL, NULL);
		g_free (row);

		write (fd, urow, strlen (urow));
		g_free (urow);
		cur = cur->next;
		i++;
	}

	close (fd);

	return;
}

void
grg_recent_dox_push (const gchar * file)
{
	GSList *cur, *tmp;

	if (file == NULL)
		return;

	tmp = grg_recent_dox;
	while (tmp)
	{
		cur = tmp;
		tmp = tmp->next;
		if (STR_EQ (cur->data, file) ||
		    (g_slist_position (grg_recent_dox, cur) >=
		     GRG_RECENT_LIMIT - 1))
		{
			grg_recent_dox =
				g_slist_remove_link (grg_recent_dox, cur);
			g_free (cur->data);
			g_slist_free_1 (cur);
		}
	}

	grg_recent_dox =
		g_slist_prepend (grg_recent_dox, g_strdup (file));

	recent_dox_save ();
	grg_menu_update ();
}
