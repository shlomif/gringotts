/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_prefs_io.c - preferences load/saving
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
#include <stdlib.h>
#include <math.h>

#include <gtk/gtk.h>

#include "grg_prefs.h"
#include "grg_prefs_io.h"
#include "grg_defs.h"
#include "gringotts.h"
#include "grg_safe.h"

gint
grg_save_prefs (void)
{
	gchar *path, *row, algo, *grg_pref_file_local,
		*grg_pref_font_string_local;
	gint fd;

	path = g_build_filename (g_get_home_dir (), ".gringotts.conf", NULL);
	fd = open (path, O_WRONLY | O_CREAT | O_TRUNC,
		   S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR);
	g_free (path);

	if (fd < 3)
	{
		close (fd);
		return GRG_PREFS_IO_ERROR;
	}

	algo = (guchar) (grg_ctx_get_crypt_algo (gctx) |
			 grg_ctx_get_hash_algo (gctx) |
			 grg_ctx_get_comp_algo (gctx) |
			 grg_ctx_get_comp_ratio (gctx));

	/*saves the algorithm */
	row = g_strdup_printf
		("<!-- You'd better not to modify these values manually, anyway -->\n\n<!-- Not human-readable -->\n<algo_code>\n%02x\n</algo_code>\n\n",
		 algo);
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the startup file */
	grg_pref_file_local = get_pref_file ();
	if (grg_pref_file_local)
	{
		row = g_strdup_printf
			("<!-- A valid filepath -->\n<startup_file>\n%s\n</startup_file>\n\n",
			 grg_pref_file_local);
		g_free (grg_pref_file_local);
		write (fd, row, strlen (row));
		g_free (row);
	}

	/*saves the backup files preference */
	row = g_strdup_printf
		("<!-- 0/1 -->\n<bak_files>\n%c\n</bak_files>\n\n",
		 grg_prefs_bak_files ? '1' : '0');
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the file overwriting warning preference */
	row = g_strdup_printf
		("<!-- 0/1 -->\n<overwrite_warn>\n%c\n</overwrite_warn>\n\n",
		 grg_prefs_warn4overwrite ? '1' : '0');
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the splash screen preference */
	row = g_strdup_printf
		("<!-- 0/1 -->\n<display_splash_screen>\n%c\n</display_splash_screen>\n\n",
		 grg_prefs_splash ? '1' : '0');
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the password expiration time preference */
	row = g_strdup_printf
		("<!-- %d-%d, negative = off -->\n<xpiration_time>\n%d\n</xpiration_time>\n\n",
		 EXP_TIME_MIN, EXP_TIME_MAX, grg_prefs_xpire);
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the wipe passes preference */
	row = g_strdup_printf
		("<!-- %d-%d -->\n<wipe_passes>\n%d\n</wipe_passes>\n\n",
		 WIPE_PASSES_MIN, WIPE_PASSES_MAX, grg_prefs_wipe_passes);
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the font for the editor */
	grg_pref_font_string_local = get_pref_font_string ();
	if (grg_pref_font_string_local)
	{
		row = g_strdup_printf
			("<!-- A valid Pango fontname -->\n<font_for_editor>\n%s\n</font_for_editor>\n\n",
			 grg_pref_font_string_local);
		g_free (grg_pref_font_string_local);
		write (fd, row, strlen (row));
		g_free (row);
	}

	/*saves the main window size preference */
	row = g_strdup_printf
		("<!-- -1 or a valid window width -->\n<Width_of_main_window>\n%d\n</Width_of_main_window>\n\n",
		 grg_prefs_mainwin_width);
	write (fd, row, strlen (row));
	g_free (row);
	row = g_strdup_printf
		("<!-- -1 or a valid window height -->\n<Height_of_main_window>\n%d\n</Height_of_main_window>\n\n",
		 grg_prefs_mainwin_height);
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the clipboard clearing pref */
	{
		char policy =
			grg_prefs_clip_clear_on_close ? '2'
			: (grg_prefs_clip_clear_on_quit ? '1' : '0');
		row = g_strdup_printf
			("<!-- 0: never; 1: on quit; 2: on file close -->\n<clipboard_clearing_policy>\n%c\n</clipboard_clearing_policy>",
			 policy);
		write (fd, row, strlen (row));
		g_free (row);
	}

	close (fd);

	return GRG_OK;
}

#define IGNORE		'\0'
#define ALGO		'a'
#define START_FILE	's'
#define OVER		'o'
#define BACKUP		'b'
#define SPLASH		'd'
#define XPIRE_TIME	'x'
#define WIPE_PASSES	'w'
#define EDITOR_FONT	'f'
#define CLIPCLEAR	'c'
#define MAINWIN_WIDTH 'W'
#define MAINWIN_HEIGHT 'H'

static void
introduce_pref (GMarkupParseContext * context,
		const gchar * element_name,
		const gchar ** attribute_names,
		const gchar ** attribute_values,
		gpointer user_data, GError ** error)
{
	*((gchar *) user_data) = element_name[0];
}

static void
collect_pref (GMarkupParseContext * context,
	      const gchar * text,
	      gsize text_len, gpointer user_data, GError ** error)
{
	switch (*((gchar *) user_data))
	{
	case IGNORE:
		break;
	case ALGO:
	{
		gchar algo1 = 0, algo2 = 0, algo;
		gint i, pos = 0;
		for (i = 0; i < text_len; i++)	/*strips whitespaces*/
			if ((text[i] != ' ') && (text[i] != '\t')
			    && (text[i] != '\n'))
			{
				if (!pos)	/*pos=0*/
					algo1 = text[i];
				else
					algo2 = text[i];
				pos++;
			}

		if (!
		    (((algo1 >= '0') && (algo1 <= '9'))
		     || ((algo1 >= 'a') && (algo1 <= 'f')))
		    || !(((algo2 >= '0') && (algo2 <= '9'))
			 || ((algo2 >= 'a') && (algo2 <= 'f'))))
			break;
		/*form the algo byte and setup values*/
		if (algo1 < 'a')
			algo1 -= '0';
		else
			algo1 -= 'W';	/*'a'-10*/

		if (algo2 < 'a')
			algo2 -= '0';
		else
			algo2 -= 'W';	/*'a'-10*/

		algo = 0;
		algo |= (guchar) ((algo1 << 4) & 0xf0);
		algo |= (guchar) (algo2 & 0x0f);

		grg_ctx_set_crypt_algo (gctx, (grg_crypt_algo) (algo & 0x70	/* 01110000 */
					));
		grg_ctx_set_hash_algo (gctx,
				       (grg_hash_algo) (algo & 0x08
							/* 00001000 */ ));
		grg_ctx_set_comp_algo (gctx,
				       (grg_comp_algo) (algo & 0x04
							/* 00000100 */ ));
		grg_ctx_set_comp_ratio (gctx, (grg_comp_ratio) (algo & 0x03	/* 00000011 */
					));

		break;
	}
	case START_FILE:
	{
		if (text_len == 0)
			set_pref_file (NULL);
		else
		{
			gchar *file = g_strstrip (g_strndup (text, text_len));
			gchar *utf =
				g_filename_from_utf8 (file, -1, NULL, NULL,
						      NULL);
			gint fdt = open (utf, O_RDONLY);
			if (fdt < 3)
				set_pref_file (NULL);
			else
				set_pref_file (file);
			close (fdt);
			g_free (file);
			g_free (utf);
		}
		break;
	}
	case OVER:
	{
		int i = 0;
		while (text[i] == 10 || text[i] == ' ' || text[i] == '\t'
		       || text[i] == 13)
			i++;
		grg_prefs_warn4overwrite = !(text[i] == '0');
		break;
	}
	case BACKUP:
	{
		int i = 0;
		while (text[i] == 10 || text[i] == ' ' || text[i] == '\t'
		       || text[i] == 13)
			i++;
		grg_prefs_bak_files = !(text[i] == '0');
		break;
	}
	case SPLASH:
	{
		int i = 0;
		while (text[i] == 10 || text[i] == ' ' || text[i] == '\t'
		       || text[i] == 13)
			i++;
		grg_prefs_splash = !(text[i] == '0');
		break;
	}
	case XPIRE_TIME:
	{
		int i = 0, grgabs;
		while ((text[i] < '1' || text[i] > '9') && text[i] != '-')
			i++;
		grg_prefs_xpire = atoi (text + i);
		grgabs = abs (grg_prefs_xpire);
		if (grgabs < EXP_TIME_MIN || grgabs > EXP_TIME_MAX)
			grg_prefs_xpire = EXP_TIME_DEF;
		break;
	}
	case WIPE_PASSES:
	{
		int i = 0;
		while (text[i] < '1' || text[i] > '9')
			i++;
		grg_prefs_wipe_passes = atoi (text + i);
		if (grg_prefs_wipe_passes < WIPE_PASSES_MIN
		    || grg_prefs_wipe_passes > WIPE_PASSES_MAX)
			grg_prefs_wipe_passes = WIPE_PASSES_DEF;
		break;
	}
	case EDITOR_FONT:
	{
		if (text_len == 0)
			set_pref_font_string (NULL);
		else
		{
			gchar *font = g_strstrip (g_strndup (text, text_len));
			set_pref_font_string (font);
			g_free (font);
		}
		break;
	}
	case CLIPCLEAR:
	{
		int i = 0;
		while (text[i] < '0' || text[i] > '2')
			i++;
		grg_prefs_clip_clear_on_close = (text[i] == '2');
		grg_prefs_clip_clear_on_quit = !(text[i] == '0');
		break;
	}
	case MAINWIN_WIDTH:
	{
		int i = 0;
		while ((text[i] < '1' || text[i] > '9') && text[i] != '-')
			i++;
		grg_prefs_mainwin_width = atoi (text + i);
		if (grg_prefs_mainwin_width < -1)
			grg_prefs_mainwin_width = -1;
		break;
	}
	case MAINWIN_HEIGHT:
	{
		int i = 0;
		while ((text[i] < '1' || text[i] > '9') && text[i] != '-')
			i++;
		grg_prefs_mainwin_height = atoi (text + i);
		if (grg_prefs_mainwin_height < -1)
			grg_prefs_mainwin_height = -1;
		break;
	}
	}
	*((gchar *) user_data) = IGNORE;
}

gint
grg_load_prefs (void)
{
	gchar *path, *content, active_opt = 0;
	gint fd, end;
	GMarkupParser *context =
		(GMarkupParser *) grg_malloc (sizeof (GMarkupParser));
	GMarkupParseContext *parser;
	GError *err = NULL;

	path = g_build_filename (g_get_home_dir (), ".gringotts.conf", NULL);
	fd = open (path, O_RDONLY);
	g_free (path);

	if (fd < 3)
	{
		close (fd);
		return GRG_PREFS_IO_ERROR;
	}

	end = lseek (fd, 0, SEEK_END);
	lseek (fd, 0, SEEK_SET);

	context->start_element = introduce_pref;
	context->end_element = NULL;
	context->text = collect_pref;
	context->passthrough = NULL;
	context->error = NULL;

	parser = g_markup_parse_context_new (context, 0, &active_opt, NULL);

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

	return GRG_OK;
}
