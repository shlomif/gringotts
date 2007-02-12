/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_entries.c - functions to manage the GList of Gringotts' entries
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

#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "grg_defs.h"
#include "gringotts.h"
#include "grg_prefs.h"
#include "grg_safe.h"
#include "grg_widgets.h"
#include "grg_recent_dox.h"
#include "grg_attachs.h"

#include <libgringotts.h>

static GList *entries = NULL;
GList *current = NULL;
static gchar *serialized;
static gint pos_to_restore;
static gboolean newer_data = FALSE;
static gchar *afname, *afcomment;

/**
 * meta_free:
 * @data: the callback's data
 * @user_data: the callback's user-defined data
 *
 * Frees a single node. Used only by grg_entries_free()
 */
static void
meta_free (gpointer data, gpointer user_data)
{
	struct grg_entry *entry = (struct grg_entry *) data;

	GRGAFREE (entry->entryID);
	entry->entryID = NULL;
	GRGAFREE (entry->entryBody);
	entry->entryBody = NULL;
	grg_attach_list_free (entry->attach);
	entry->attach = NULL;
	g_free (entry);
	entry = NULL;
}

/**
 * grg_entries_append:
 * @ID: the title of the new entry
 *
 * Appends a new entry to the list
 */
void
grg_entries_append (void)
{
	struct grg_entry *entry;

	entry = grg_malloc (sizeof (struct grg_entry));

	entry->entryID = g_strdup ("");
	entry->entryBody = g_strdup ("");
	entry->attach = NULL;

	entries = g_list_append (entries, entry);
	current = g_list_last (entries);
}

/**
 * grg_entries_remove:
 *
 * Removes the current entry and frees it
 */
void
grg_entries_remove (void)
{
	gint pos;

	if (!current)
		return;

	pos = g_list_position (entries, current);
	meta_free (current->data, NULL);
	entries = g_list_remove_link (entries, current);
	g_list_free_1 (current);
	current = g_list_nth (entries, pos);
	if (!current)
		current = g_list_nth (entries, pos - 1);
}

/**
 * grg_entries_is_first:
 *
 * Tells if the current entry is the first one
 *
 * Returns: TRUE if true, FALSE if false.
 */
gboolean
grg_entries_is_first (void)
{
	if (!current)
		return TRUE;

	if (!current->prev)
		return TRUE;

	return FALSE;
}

/**
 * grg_entries_is_last:
 *
 * Tells if the current entry is the last one
 *
 * Returns: TRUE if true, FALSE if false.
 */
gboolean
grg_entries_is_last (void)
{
	if (!current)
		return TRUE;

	if (!current->next)
		return TRUE;

	return FALSE;
}

/**
 * grg_entries_is_empty:
 *
 * Tells if the current list is empty
 *
 * Returns: TRUE if true, FALSE if false.
 */
gboolean
grg_entries_is_empty (void)
{
	return (entries == NULL);
}

/**
 * grg_entries_first:
 *
 * Goes to the first entry
 */
void
grg_entries_first (void)
{
	current = g_list_first (entries);
}

/**
 * grg_entries_prev:
 *
 * Goes to the previous entry
 */
void
grg_entries_prev (void)
{
	if (current->prev)
		current = g_list_previous (current);
}

/**
 * grg_entries_next:
 *
 * Goes to the next entry
 */
void
grg_entries_next (void)
{
	if (current->next)
		current = g_list_next (current);
}

/**
 * grg_entries_last:
 *
 * Goes to the last entry
 */
void
grg_entries_last (void)
{
	current = g_list_last (entries);
}

/**
 * grg_entries_nth:
 * @pos: the position to go to
 *
 * Goes to the specified entry, if possible
 */
void
grg_entries_nth (gint pos)
{
	current = g_list_nth (entries, pos);
}

/**
 * grg_entries_position:
 *
 * Tells the position of the current entry in the list
 *
 * Returns: a gint with the position
 */
gint
grg_entries_position (void)
{
	if (!current)
		return -1;

	return g_list_position (entries, current);
}

/**
 * grg_entries_raise
 *
 * Shifts one position up
 */
void
grg_entries_raise (void)
{
	gpointer ent;

	if (!current->prev)
		return;

	ent = current->data;
	current->data = current->prev->data;
	current->prev->data = ent;
}

/**
 * grg_entries_sink
 *
 * Shifts one position down
 */
void
grg_entries_sink (void)
{
	gpointer ent;

	if (!current->next)
		return;

	ent = current->data;
	current->data = current->next->data;
	current->next->data = ent;
}

/**
 * grg_entries_get_ID
 *
 * Returns the title of the current entry.
 *
 * Returns: a gchar* with the title (NOT a copy), or NULL if the list is empty
 */
gchar *
grg_entries_get_ID (void)
{
	if (current)
		return ((struct grg_entry *) current->data)->entryID;
	return NULL;
}

/**
 * grg_entries_get_Body
 *
 * Returns the body text of the current entry.
 *
 * Returns: a gchar* with the text, or NULL if the list is empty
 */
gchar *
grg_entries_get_Body (void)
{
	if (current)
		return ((struct grg_entry *) current->data)->entryBody;
	return NULL;
}

static void
grg_entries_set_ID_asis (gchar * ID)
{
	if (current)
	{
		GRGAFREE (((struct grg_entry *) current->data)->entryID);
		((struct grg_entry *) current->data)->entryID = ID;
	}
	else
		GRGAFREE (ID);
}

/**
 * grg_entries_set_ID
 * @ID: the text to store
 *
 * Stores the given title in the current entry.
 */
void
grg_entries_set_ID (const gchar * ID)
{
	if (ID)
		grg_entries_set_ID_asis (g_strdup (ID));
}

static void
grg_entries_set_Body_asis (gchar * Body)
{
	if (current)
	{
		GRGAFREE (((struct grg_entry *) current->data)->entryBody);
		((struct grg_entry *) current->data)->entryBody = Body;
	}
	else
		GRGAFREE (Body);
}

/**
 * grg_entries_set_Body
 * @Body: the text to store
 *
 * Stores the given text as the body of the current entry.
 */
void
grg_entries_set_Body (const gchar * Body)
{
	if (Body)
		grg_entries_set_Body_asis (g_strdup (Body));
}

/**
 * grg_entries_free:
 *
 * Deletes and frees all the list
 */
void
grg_entries_free (void)
{
	if (!entries)
		return;

	g_list_foreach (entries, meta_free, NULL);
	g_list_free (entries);
	entries = NULL;
	current = NULL;
}

static void
meta_print (gpointer data, gpointer user_data)
{
	static int i = 0;	//it's used only for one call of grg_entries_print; it works only if so
	int j = GPOINTER_TO_UINT (user_data);
	struct grg_entry *entry = (struct grg_entry *) data;
	g_print ("   **********\n%d: %s\n   **********\n\n",
		 (j == 0 ? ++i : j), entry->entryID);
	g_print ("%s\n\n", entry->entryBody);
}

guint grg_entries_n_el (void);

void
grg_entries_print (gint ennum, gchar * enpage)
{
	gchar *utfenpage = NULL;
	gsize ulen;
	if (ennum < 0 && enpage == NULL)
	{
		g_list_foreach (entries, meta_print, GUINT_TO_POINTER (0));
		return;
	}
	if (ennum > -1)
	{
		if (ennum > grg_entries_n_el () || ennum == 0)
			report_err (_("Invalid entry number"), 0, 1, NULL);	//and quit
		grg_entries_nth (ennum - 1);
		meta_print (current->data, GUINT_TO_POINTER (ennum));
		return;
	}
	grg_entries_first ();

	if (!mapIsUTF)
		utfenpage = g_locale_to_utf8 (enpage, -1, NULL, &ulen, NULL);

	while (current)
	{
		if (STR_EQ
		    (grg_entries_get_ID (), mapIsUTF ? enpage : utfenpage))
			meta_print (current->data,
				    GUINT_TO_POINTER (grg_entries_position ()
						      + 1));
		current = current->next;
	}

	if (!mapIsUTF)
		GRGFREE (utfenpage, ulen);
}

/**
 * meta_save:
 * @data: the callback's data
 * @user_data: the callback's user-defined data
 *
 * "serializes" a single node. Used only by grg_entries_save()
 */
static void
meta_save (gpointer data, gpointer user_data)
{
	struct grg_entry *entry = (struct grg_entry *) data;
	gchar *eBody, *eID, *res, *attachments;
	gint dim;
	GList *attlist;

	dim = strlen (entry->entryBody);
	eBody = g_markup_escape_text (entry->entryBody, dim);

	dim = strlen (entry->entryID);
	eID = g_markup_escape_text (entry->entryID, dim);

	attlist = entry->attach;
	attachments = g_strdup ("");
#define XML_ATT_FORMAT	"%s\n<attachment name=\"%s\" comment=\"%s\">%s</attachment>"
	while (attlist)
	{
		struct grg_attachment *att =
			(struct grg_attachment *) attlist->data;
        void * void_origfile;
		gchar *origfile, *b64file, *append;

		grg_get_content (att, &void_origfile, NULL);
        origfile = (gchar*)void_origfile;
		b64file = (gchar*)grg_encode64 ((guchar*)origfile, att->filedim, NULL);
		GRGFREE (void_origfile, att->filedim);
		append = g_strdup_printf (XML_ATT_FORMAT, attachments,
					  att->filename, att->comment,
					  b64file);
		GRGAFREE (b64file);
		GRGAFREE (attachments);
		attachments = append;
		attlist = attlist->next;
	}

#define XML_ENTRY_FORMAT	"%s\n<entry>\n<title>%s</title>\n<body>%s</body>%s\n</entry>"
	res = g_strdup_printf (XML_ENTRY_FORMAT, serialized, eID, eBody,
			       attachments);

	GRGAFREE (eBody);
	eBody = NULL;
	GRGAFREE (eID);
	eID = NULL;

	GRGAFREE (serialized);
	serialized = g_strdup (res);

	GRGAFREE (res);
	res = NULL;
}

/**
 * grg_entries_save:
 * @file: the path of the file to save
 * @key: the keyring to use
 *
 * Saves the list into an encrypted file
 *
 * Returns: GRG_OK if all is well, an error if not
 */
gint
grg_entries_save (gchar * file, GRG_KEY key, GtkWidget * parent)
{
	gint err, pos = grg_entries_position ();
	GtkWidget *wait;

	if (pwdbirth == 0)
		pwdbirth = time (NULL);

	wait = grg_wait_msg (_("assembling data"), parent);

	serialized = g_strdup_printf
		("<save_file_fmt_version>" GRG_FILE_SUBVERSION
		 "</save_file_fmt_version>" "\n<position>%d</position>"
		 "\n<regen_pwd_time>%ld</regen_pwd_time>", pos, pwdbirth);

	g_list_foreach (entries, meta_save, NULL);

	grg_wait_message_change_reason (wait, _("saving"));

	err = grg_encrypt_file (gctx, key, (guchar*)file, (guchar*)serialized,
				strlen (serialized));

	grg_wait_message_change_reason (wait, _("cleaning up"));

	GRGAFREE (serialized);
	serialized = NULL;

	gtk_widget_destroy (wait);

	if (err != GRG_OK)
		return err;

	grg_recent_dox_push (file);
	return GRG_OK;
}

//the letter denoting the field is the first of the tag text
#define	VERS_FIELD		's'
#define TITLE_FIELD		't'
#define BODY_FIELD		'b'
#define POSITION_FIELD	'p'
#define IGNORE_FIELD	'e'
#define REGEN_PWD_FIELD	'r'
#define ATTACH_FIELD	'a'

static void
get_tag (GMarkupParseContext * context,
	 const gchar * element_name,
	 const gchar ** attribute_names,
	 const gchar ** attribute_values, gpointer user_data, GError ** error)
{
	*((gchar *) user_data) = element_name[0];
	if (element_name[0] == 'a')
	{
		afname = g_strdup (attribute_values[0]);
		afcomment = g_strdup (attribute_values[1]);
	}
}

static void
trash_tag (GMarkupParseContext * context,
	   const gchar * element_name, gpointer user_data, GError ** error)
{
	*((gchar *) user_data) = IGNORE_FIELD;
}

static void
compose_entry (GMarkupParseContext * context,
	       const gchar * text,
	       gsize text_len, gpointer user_data, GError ** error)
{
	switch (*((gchar *) user_data))
	{
	case TITLE_FIELD:
		grg_entries_append ();
		grg_entries_set_ID (text);
		break;
	case BODY_FIELD:
		grg_entries_set_Body (text);
		break;
	case POSITION_FIELD:
		pos_to_restore = atoi (text);
		break;
	case VERS_FIELD:
		newer_data = (text[0] > GRG_FILE_SUBVERSION[0]);
		break;
	case REGEN_PWD_FIELD:
		pwdbirth = atol (text);
		break;
	case ATTACH_FIELD:
	{
		guint dim;
		gchar *decoded = (gchar*)grg_decode64 ((guchar*)text, text_len, &dim);
		grg_attach_content (decoded, dim, afname, afcomment);
		GRGFREE (decoded, dim);
		GRGAFREE (afname);
		afname = NULL;
		GRGAFREE (afcomment);
		afcomment = NULL;
	}
		break;
	}
}

/**
 * grg_entries_load_from_string:
 * @str: the string which contains the data, XML (file format 3)
 *
 * "de-serializes" a (XML) string into an entry list
 */
void
grg_entries_load_from_string (gchar * str, GtkWidget * parent, gboolean X)
{
	gint end;
	gchar field;
	GMarkupParser *context;
	GMarkupParseContext *parser;
	GError *err = NULL;

	grg_entries_free ();

	context = (GMarkupParser *) grg_malloc (sizeof (GMarkupParser));
	context->start_element = get_tag;
	context->end_element = trash_tag;
	context->text = compose_entry;
	context->passthrough = NULL;
	context->error = NULL;

	parser = g_markup_parse_context_new (context, 0, (gpointer) & field,
					     NULL);
	end = strlen (str);

	g_markup_parse_context_parse (parser, str, end, &err);
	if (!err)
		g_markup_parse_context_end_parse (parser, &err);

	g_markup_parse_context_free (parser);
	if (err)
		g_error_free (err);
	g_free (context);

	grg_entries_nth (pos_to_restore);

	if (newer_data)
		report_err (_
			    ("The file has been created with a newer version of Gringotts. "
			     "If you save it using this one, some formatting can be lost."),
			    X, 0, parent);
}

/**
 * grg_load_wrapper:
 * @txt: a pointer to a byte sequence to store the data in. It must be freed after use!
 * @pwd: the password to decode data
 * @fd: a file pointer to read data from
 * 
 * Wrapper to grg_load_crypted, to add UTF-8 validation.
 *
 * Returns: 0 if OK; an error code otherwise (see libgringotts' docs)
 */
gint
grg_load_wrapper (gchar ** txt, GRG_KEY key, const gint fd,
		  const gchar * file)
{
	gint err;
	glong len = 0;
    guchar *unsigned_txt;

    /* I'm doing this assignment in and out because one cannot guarantee that
     * pointers of different types will be the same.
     * */
    unsigned_txt = (guchar*)*txt;
	err = grg_decrypt_file_direct (gctx, key, fd, &unsigned_txt, &len);
    *txt = (gchar*)unsigned_txt;

	grg_prefs_update ();

	if (err != GRG_OK)
		return err;

	if (!g_utf8_validate (*txt, len, NULL))
		return GRG_READ_INVALID_CHARSET_ERR;

	grg_recent_dox_push (file);
	return GRG_OK;
}

/**
 * grg_entries_n_el:
 *
 * Tells how many elements does the list contain
 *
 * Returns: a guint with the elements' number
 */
guint
grg_entries_n_el (void)
{
	if (entries)
		return g_list_length (entries);
	else
		return 0;
}

/**
 * grg_entries_n_att:
 *
 * Tells how many files are attached to the current entry
 *
 * Returns: a guint with the files' number
 */
guint
grg_entries_n_att (void)
{
	if (current)
		return g_list_length (((struct grg_entry *) current->data)->
				      attach);
	else
		return 0;
}

/**
 * grg_entries_find:
 * @needle: the text to find
 * @offset: the offset to search from
 * @only_current: if TRUE, consider only the current entry
 * @case_sens: wheter to be case sensitive or not
 *
 * Searches for a text in the entries.
 *
 * Returns: the offset of the found text, -1 if not found
 */
glong
grg_entries_find (gchar * needle, glong offset, gboolean only_current,
		  gboolean case_sens)
{
	gchar *text = grg_entries_get_Body (), *start =
		g_utf8_offset_to_pointer (text, offset), *occur;
	glong result;

	if (case_sens)
	{
		occur = g_strstr_len (start, strlen (start), needle);

		if (occur)
			result = g_utf8_pointer_to_offset (text,
							   occur) + offset;
		else
			result = -1;
	}
	else
	{
		gchar *tok1, *tok2;
		gulong len;

		tok1 = g_utf8_casefold (start, -1);
		tok2 = g_utf8_casefold (needle, -1);
		len = strlen (tok1);

		occur = g_strstr_len (tok1, len, tok2);

		if (occur)
			result = g_utf8_pointer_to_offset (tok1,
							   occur) + offset;
		else
			result = -1;

		GRGFREE (tok1, len);
		tok1 = NULL;
		GRGAFREE (tok2);
		tok2 = NULL;
	}

	if (result < 0)
	{
		gint cur = grg_entries_position (), ret;

		if (only_current)
			return -1;

		if (grg_entries_is_last ())
			return -1;
		else
			grg_entries_next ();

		ret = grg_entries_find (needle, 0, FALSE, case_sens);
		if (ret == -1)
			grg_entries_nth (cur);
		return ret;
	}
	
	/* FIXME: this update() is quite misplaced, it's not meant to be
	  called directly */
	update();
	
	return result;
}
