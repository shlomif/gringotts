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

#define PREFS_TAG_ALGO						"algo_code"
#define PREFS_TAG_STARTUP_FILE				"startup_file"
#define PREFS_TAG_OVERWRITE_WARN			"overwrite_warn"
#define PREFS_TAG_BACKUP_FILES				"bak_files"
#define PREFS_TAG_DISPLAY_SPLASH_SCREEN		"display_splash_screen"
#define PREFS_TAG_PASSWORD_EXPIRATION_TIME	"xpiration_time"
#define PREFS_TAG_WIPE_PASSES				"wipe_passes"
#define PREFS_TAG_EDITOR_FONT				"font_for_editor"
#define PREFS_TAG_CLIPBOARD_CLEARING_POLICY	"clipboard_clearing_policy"
#define PREFS_TAG_MAINWIN_WIDTH 			"Width_of_main_window"
#define PREFS_TAG_MAINWIN_HEIGHT 			"Height_of_main_window"

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
		("<!-- You'd better not to modify these values manually, anyway -->\n\n"
		 "<!-- Not human-readable -->\n"
		 "<" PREFS_TAG_ALGO ">\n"
		 "%02x\n"
		 "</" PREFS_TAG_ALGO ">\n\n",
		 algo);
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the startup file */
	grg_pref_file_local = get_pref_file ();
	if (grg_pref_file_local)
	{
		row = g_strdup_printf
			("<!-- A valid filepath -->\n"
			 "<" PREFS_TAG_STARTUP_FILE ">\n"
			 "%s\n"
			 "</" PREFS_TAG_STARTUP_FILE ">\n\n",
			 grg_pref_file_local);
		g_free (grg_pref_file_local);
		write (fd, row, strlen (row));
		g_free (row);
	}

	/*saves the backup files preference */
	row = g_strdup_printf
		("<!-- 0/1 -->\n"
		 "<" PREFS_TAG_BACKUP_FILES ">\n"
		 "%c\n"
		 "</" PREFS_TAG_BACKUP_FILES ">\n\n",
		 grg_prefs_bak_files ? '1' : '0');
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the file overwriting warning preference */
	row = g_strdup_printf
		("<!-- 0/1 -->\n"
		 "<" PREFS_TAG_OVERWRITE_WARN ">\n"
		 "%c\n"
		 "</" PREFS_TAG_OVERWRITE_WARN ">\n\n",
		 grg_prefs_warn4overwrite ? '1' : '0');
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the splash screen preference */
	row = g_strdup_printf
		("<!-- 0/1 -->\n"
		 "<" PREFS_TAG_DISPLAY_SPLASH_SCREEN ">\n"
		 "%c\n"
		 "</" PREFS_TAG_DISPLAY_SPLASH_SCREEN ">\n\n",
		 grg_prefs_splash ? '1' : '0');
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the password expiration time preference */
	row = g_strdup_printf
		("<!-- %d-%d, negative = off -->\n"
		 "<" PREFS_TAG_PASSWORD_EXPIRATION_TIME ">\n"
		 "%d\n"
		 "</" PREFS_TAG_PASSWORD_EXPIRATION_TIME ">\n\n",
		 EXP_TIME_MIN, EXP_TIME_MAX, grg_prefs_xpire);
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the wipe passes preference */
	row = g_strdup_printf
		("<!-- %d-%d -->\n"
		 "<" PREFS_TAG_WIPE_PASSES ">\n"
		 "%d\n"
		 "</" PREFS_TAG_WIPE_PASSES ">\n\n",
		 WIPE_PASSES_MIN, WIPE_PASSES_MAX, grg_prefs_wipe_passes);
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the font for the editor */
	grg_pref_font_string_local = get_pref_font_string ();
	if (grg_pref_font_string_local)
	{
		row = g_strdup_printf
		("<!-- A valid Pango fontname -->\n"
		 "<" PREFS_TAG_EDITOR_FONT ">\n"
		 "%s\n"
		 "</" PREFS_TAG_EDITOR_FONT ">\n\n",
			 grg_pref_font_string_local);
		g_free (grg_pref_font_string_local);
		write (fd, row, strlen (row));
		g_free (row);
	}

	/*saves the main window size preference */
	row = g_strdup_printf
		("<!-- -1 or a valid window width -->\n"
		 "<" PREFS_TAG_MAINWIN_WIDTH ">\n"
		 "%d\n"
		 "</" PREFS_TAG_MAINWIN_WIDTH ">\n\n",
		 grg_prefs_mainwin_width);
	write (fd, row, strlen (row));
	g_free (row);
	row = g_strdup_printf
		("<!-- -1 or a valid window height -->\n"
		 "<" PREFS_TAG_MAINWIN_HEIGHT ">\n"
		 "%d\n"
		 "</" PREFS_TAG_MAINWIN_HEIGHT ">\n\n",
		 grg_prefs_mainwin_height);
	write (fd, row, strlen (row));
	g_free (row);

	/*saves the clipboard clearing pref */
	{
		char policy =
			grg_prefs_clip_clear_on_close ? '2'
			: (grg_prefs_clip_clear_on_quit ? '1' : '0');
		row = g_strdup_printf
			("<!-- 0: never; 1: on quit; 2: on file close -->\n"
			 "<" PREFS_TAG_CLIPBOARD_CLEARING_POLICY ">\n"
			 "%c\n"
			 "</" PREFS_TAG_CLIPBOARD_CLEARING_POLICY ">",
			 policy);
		write (fd, row, strlen (row));
		g_free (row);
	}

	close (fd);

	return GRG_OK;
}

static void
introduce_pref (GMarkupParseContext * context,
		const gchar * element_name,
		const gchar ** attribute_names,
		const gchar ** attribute_values,
		gpointer user_data, GError ** error)
{
	if (user_data)
		*(gchar**) user_data = g_strdup(element_name);
}

static void
endup_pref (GMarkupParseContext * context,
		const gchar * element_name,
		gpointer user_data, GError ** error)
{
	if (user_data && *(gchar**) user_data)
	{
		g_free(*(gchar**) user_data);
		*(gchar**) user_data = NULL;
	}
}

static void
collect_pref (GMarkupParseContext * context,
	      const gchar * text,
	      gsize text_len, gpointer user_data, GError ** error)
{
	if (strcmp(*(gchar **) user_data, PREFS_TAG_ALGO)==0)
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

		if ((((algo1 >= '0') && (algo1 <= '9'))
		     || ((algo1 >= 'a') && (algo1 <= 'f')))
		    || !(((algo2 >= '0') && (algo2 <= '9'))
			 || ((algo2 >= 'a') && (algo2 <= 'f'))))
		{
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
		}
	} else
	if (strcmp(*(gchar **) user_data, PREFS_TAG_STARTUP_FILE)==0)
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
	} else
	if (strcmp(*(gchar **) user_data, PREFS_TAG_OVERWRITE_WARN)==0)
	{
		int i = 0;
		while (text[i] == 10 || text[i] == ' ' || text[i] == '\t'
		       || text[i] == 13)
			i++;
		grg_prefs_warn4overwrite = !(text[i] == '0');
	} else
	if (strcmp(*(gchar **) user_data, PREFS_TAG_BACKUP_FILES)==0)
	{
		int i = 0;
		while (text[i] == 10 || text[i] == ' ' || text[i] == '\t'
		       || text[i] == 13)
			i++;
		grg_prefs_bak_files = !(text[i] == '0');
	} else
	if (strcmp(*(gchar **) user_data, PREFS_TAG_DISPLAY_SPLASH_SCREEN)==0)
	{
		int i = 0;
		while (text[i] == 10 || text[i] == ' ' || text[i] == '\t'
		       || text[i] == 13)
			i++;
		grg_prefs_splash = !(text[i] == '0');
	} else
	if (strcmp(*(gchar **) user_data, PREFS_TAG_PASSWORD_EXPIRATION_TIME)==0)
	{
		int i = 0, grgabs;
		while ((text[i] < '1' || text[i] > '9') && text[i] != '-')
			i++;
		grg_prefs_xpire = atoi (text + i);
		grgabs = abs (grg_prefs_xpire);
		if (grgabs < EXP_TIME_MIN || grgabs > EXP_TIME_MAX)
			grg_prefs_xpire = EXP_TIME_DEF;
	} else
	if (strcmp(*(gchar **) user_data, PREFS_TAG_WIPE_PASSES)==0)
	{
		int i = 0;
		while (text[i] < '1' || text[i] > '9')
			i++;
		grg_prefs_wipe_passes = atoi (text + i);
		if (grg_prefs_wipe_passes < WIPE_PASSES_MIN
		    || grg_prefs_wipe_passes > WIPE_PASSES_MAX)
			grg_prefs_wipe_passes = WIPE_PASSES_DEF;
	} else
	if (strcmp(*(gchar **) user_data, PREFS_TAG_EDITOR_FONT)==0)
	{
		if (text_len == 0)
			set_pref_font_string (NULL);
		else
		{
			gchar *font = g_strstrip (g_strndup (text, text_len));
			set_pref_font_string (font);
			g_free (font);
		}
	} else
	if (strcmp(*(gchar **) user_data, PREFS_TAG_CLIPBOARD_CLEARING_POLICY)==0)
	{
		int i = 0;
		while (text[i] < '0' || text[i] > '2')
			i++;
		grg_prefs_clip_clear_on_close = (text[i] == '2');
		grg_prefs_clip_clear_on_quit = !(text[i] == '0');
	} else
	if (strcmp(*(gchar **) user_data, PREFS_TAG_MAINWIN_WIDTH)==0)
	{
		int i = 0;
		while ((text[i] < '1' || text[i] > '9') && text[i] != '-')
			i++;
		grg_prefs_mainwin_width = atoi (text + i);
		if (grg_prefs_mainwin_width < -1)
			grg_prefs_mainwin_width = -1;
	} else
	if (strcmp(*(gchar **) user_data, PREFS_TAG_MAINWIN_HEIGHT)==0)
	{
		int i = 0;
		while ((text[i] < '1' || text[i] > '9') && text[i] != '-')
			i++;
		grg_prefs_mainwin_height = atoi (text + i);
		if (grg_prefs_mainwin_height < -1)
			grg_prefs_mainwin_height = -1;
	} else
		fprintf(stderr, "prefs parsing error: unexpected tag '%s'\n", (gchar *) user_data);
}

gint
grg_load_prefs (void)
{
	gchar *path, *content, *active_opt = NULL;
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
	context->end_element = endup_pref;
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
