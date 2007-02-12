/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_entries_vis.c - generate and manage the widget for entry contents
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

#include <gtk/gtk.h>

#include "grg_defs.h"
#include "grg_entries_vis.h"
#include "gringotts.h"
#include "grg_entries.h"
#include "grg_prefs.h"
#include "grg_widgets.h"

#include <stdlib.h>

/* Properties */
enum {
	PROP_0,
	PROP_TABS_WIDTH
};

#define MAX_TAB_WIDTH			32
#define DEFAULT_TAB_WIDTH 		8

static GObjectClass *parent_class = NULL;
	
static GtkClipboard *clip = NULL;
static gboolean isThereAClip = FALSE;

static gchar *needle = NULL;

/**************
 * Sorry for the many commented pieces of code. It's work in progress...
 *************/

static int current_mode = SIMPLE_ENTRY;

static GtkTextBuffer *entryBuf = NULL;
#if 0
static GtkListStore *mdl = NULL;
#endif
static GtkCustomTextView *simpleSheet = NULL/*, *structSheet = NULL*/;
static gulong simpleSigID = 0/*, structSigID = 0*/;

static void gtk_custom_text_view_init (GtkCustomTextView *view);
static void gtk_custom_text_view_class_init (GtkCustomTextViewClass *klass);
static guint gtk_custom_text_view_get_tabs_width (GtkCustomTextView *klass);
static void	gtk_custom_text_view_set_property 		(GObject           *object,
							 guint              prop_id,
							 const GValue      *value,
							 GParamSpec        *pspec);
static void	gtk_custom_text_view_get_property		(GObject           *object,
							 guint              prop_id,
							 GValue            *value,
							 GParamSpec        *pspec);
void gtk_custom_text_view_set_tabs_width (GtkCustomTextView *view,
							 guint          width);
void gtk_source_view_set_tabs_width (GtkCustomTextView *view,
							 guint          width);
GType gtk_custom_text_view_get_type (void);
static gboolean set_tab_stops_internal (GtkCustomTextView *view);
static gint	calculate_real_tab_width 		(GtkCustomTextView     *view, 
							 guint              tab_size,
							 gchar              c);

void entries_vis_init (void){
	/*GtkTreeViewColumn *c1, *c2, *c3;
	GtkCellRenderer *cr1, *cr2, *cr3;
*/
	clip = gtk_clipboard_get (GDK_NONE);
	if (clip) //why shouldn't it?
		isThereAClip = TRUE;

	entryBuf = gtk_text_buffer_new (NULL);
	simpleSheet = g_object_new (GTK_TYPE_CUSTOM_TEXT_VIEW, NULL);
	gtk_text_view_set_buffer (GTK_TEXT_VIEW (simpleSheet), GTK_TEXT_BUFFER (entryBuf));
	gtk_text_view_set_wrap_mode (GTK_TEXT_VIEW (simpleSheet), GTK_WRAP_WORD);

	simpleSigID = g_signal_connect (G_OBJECT (entryBuf), "changed",
		G_CALLBACK (meta_saveable), GINT_TO_POINTER (GRG_SAVE_ACTIVE));
/*
	mdl = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
	structSheet = gtk_tree_view_new_with_model (GTK_TREE_MODEL (mdl));
	g_object_unref (G_OBJECT (mdl));
	
	cr1=gtk_cell_renderer_text_new ();
	cr2=gtk_cell_renderer_text_new ();
	cr3=gtk_cell_renderer_text_new ();
	c1=gtk_tree_view_column_new_with_attributes ("URL", cr1, "text", 0, NULL);
	c2=gtk_tree_view_column_new_with_attributes ("UserID", cr2, "text", 1, NULL);
	c3=gtk_tree_view_column_new_with_attributes ("Password", cr3, "text", 2, NULL);
	gtk_tree_view_append_column (GTK_TREE_VIEW (structSheet), c1);
	gtk_tree_view_append_column (GTK_TREE_VIEW (structSheet), c2);
	gtk_tree_view_append_column (GTK_TREE_VIEW (structSheet), c3);*/
}

static void
gtk_custom_text_view_init (GtkCustomTextView *view)
{
	char* htab_env = getenv("HTAB");
	int htab = DEFAULT_TAB_WIDTH;

	if (htab_env) {
		int value;
		char* chk;

		value = (int)strtol(htab_env, &chk, 10);
		if (!*chk) {
			htab = value;
		}
	}
	g_object_set(view, "tabs_width", htab, NULL);
}

static void
gtk_custom_text_view_class_init (GtkCustomTextViewClass *klass)
{
	GObjectClass	 *object_class;
	GtkTextViewClass *textview_class;
	GtkWidgetClass   *widget_class;
	
	object_class 	= G_OBJECT_CLASS (klass);
	textview_class 	= GTK_TEXT_VIEW_CLASS (klass);
	parent_class 	= g_type_class_peek_parent (klass);
	widget_class 	= GTK_WIDGET_CLASS (klass);
	
	object_class->get_property = gtk_custom_text_view_get_property;
	object_class->set_property = gtk_custom_text_view_set_property;

	g_object_class_install_property (object_class,
					 PROP_TABS_WIDTH,
					 g_param_spec_uint ("tabs_width",
							    _("Tabs Width"),
							    _("Tabs Width"),
							    1,
							    MAX_TAB_WIDTH,
							    DEFAULT_TAB_WIDTH,
							    G_PARAM_READWRITE));
}

static guint
gtk_custom_text_view_get_tabs_width (GtkCustomTextView *view)
{
	g_return_val_if_fail (view != NULL, FALSE);
	g_return_val_if_fail (GTK_IS_CUSTOM_TEXT_VIEW (view), FALSE);

	return view->tabs_width;
}

void
gtk_custom_text_view_set_tabs_width (GtkCustomTextView *view,
				guint          width)
{
	guint save_width;
	
	g_return_if_fail (GTK_CUSTOM_TEXT_VIEW (view));
	g_return_if_fail (width <= MAX_TAB_WIDTH);
	g_return_if_fail (width > 0);

	if (view->tabs_width == width)
		return;
	
	gtk_widget_ensure_style (GTK_WIDGET (view));
	
	save_width = view->tabs_width;
	view->tabs_width = width;
	if (set_tab_stops_internal (view))
	{
		g_object_notify (G_OBJECT (view), "tabs_width");
	}
	else
	{
		g_warning ("Impossible to set tabs width.");
		view->tabs_width = save_width;
	}
}

GType
gtk_custom_text_view_get_type (void)
{
	static GType our_type = 0;

	if (our_type == 0) {
		static const GTypeInfo our_info = {
			sizeof (GtkCustomTextViewClass),
			(GBaseInitFunc) NULL,
			(GBaseFinalizeFunc) NULL,
			(GClassInitFunc) gtk_custom_text_view_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (GtkCustomTextView),
			0,	/* n_preallocs */
			(GInstanceInitFunc) gtk_custom_text_view_init
		};
		our_type = g_type_register_static (GTK_TYPE_TEXT_VIEW,
						   "GtkCustomTextView",
						   &our_info, 0);
	}
	return our_type;
}

static void 
gtk_custom_text_view_set_property (GObject      *object,
			      guint         prop_id,
			      const GValue *value,
			      GParamSpec   *pspec)
{
	GtkCustomTextView *view;
	
	g_return_if_fail (GTK_IS_CUSTOM_TEXT_VIEW (object));

	view = GTK_CUSTOM_TEXT_VIEW (object);
    
	switch (prop_id)
	{
		case PROP_TABS_WIDTH:
			gtk_custom_text_view_set_tabs_width (view, 
							g_value_get_uint (value));
			break;
		
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void 
gtk_custom_text_view_get_property (GObject    *object,
			      guint       prop_id,
			      GValue     *value,
			      GParamSpec *pspec)
{
	GtkCustomTextView *view;
	
	g_return_if_fail (GTK_IS_CUSTOM_TEXT_VIEW (object));

	view = GTK_CUSTOM_TEXT_VIEW (object);
    
	switch (prop_id)
	{
		case PROP_TABS_WIDTH:
			g_value_set_uint (value,
					  gtk_custom_text_view_get_tabs_width (view));
			break;

		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static gboolean
set_tab_stops_internal (GtkCustomTextView *view)
{
	PangoTabArray *tab_array;
	gint real_tab_width;

	real_tab_width = calculate_real_tab_width (view, view->tabs_width, ' ');

	if (real_tab_width < 0)
		return FALSE;
	
	tab_array = pango_tab_array_new (1, TRUE);
	pango_tab_array_set_tab (tab_array, 0, PANGO_TAB_LEFT, real_tab_width);

	gtk_text_view_set_tabs (GTK_TEXT_VIEW (view), 
				tab_array);

	pango_tab_array_free (tab_array);

	return TRUE;
}

static gint
calculate_real_tab_width (GtkCustomTextView *view, guint tab_size, gchar c)
{
	PangoLayout *layout;
	gchar *tab_string;
	gint tab_width = 0;

	if (tab_size == 0)
		return -1;

	tab_string = g_strnfill (tab_size, c);
	layout = gtk_widget_create_pango_layout (GTK_WIDGET (view), tab_string);
	g_free (tab_string);

	if (layout != NULL) {
		pango_layout_get_pixel_size (layout, &tab_width, NULL);
		g_object_unref (G_OBJECT (layout));
		tab_width*=2;
	} else
		tab_width = -1;

	return tab_width;
}

gboolean
has_needle (void) {
	return needle != NULL;
}

void
del_needle (void) {
	if (!has_needle())
		return;

	GRGAFREE (needle);
	needle = NULL;
}

void entries_vis_deinit (void){
	if (isThereAClip && grg_prefs_clip_clear_on_quit
	    && !grg_prefs_clip_clear_on_close)
		gtk_clipboard_clear (clip);

	del_needle ();
}

GtkWidget 
*get_updated_sheet (gboolean hasData){
	//if (current_mode == SIMPLE_ENTRY) {
		g_signal_handler_block (entryBuf, simpleSigID);
		gtk_text_buffer_set_text (entryBuf,
				  hasData ? grg_entries_get_Body () : "",
				  -1);
		g_signal_handler_unblock (entryBuf, simpleSigID);
		return simpleSheet;
	/*} else {
		GtkTreeIter iter;
		
		mdl = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
		gtk_list_store_append(mdl, &iter);
		gtk_list_store_set(mdl, &iter, 0, "www.prosa.com", 1, "admin", 2, "nIitnPp", -1);
		gtk_tree_view_set_model (GTK_TREE_VIEW(structSheet), GTK_TREE_MODEL (mdl));
		return structSheet;
	}*/
}

void
clear_clipboard (void) {
	gtk_clipboard_clear (clip);
}

/**
 * sync_entry:
 *
 * Writes the information stored in the GtkTextBuffer to the
 * entry structure in memory. To be called whenever a page is
 * leaved, or saved.
 */
void
sync_entry (void)
{
	static GtkTextIter s, e;

	gtk_text_buffer_get_bounds (entryBuf, &s, &e);
	grg_entries_set_Body (gtk_text_buffer_get_text
			      (entryBuf, &s, &e, FALSE));
}

/**
 * cucopa:
 * @callback_data: unused callback param
 * @callback_action: action to perform (GRG_CUT, GRG_COPY, GRG_PASTE)
 *
 * basic CUT/COPY/PASTE clipboard operation.
 */
void
cucopa (gpointer callback_data, guint callback_action)
{
	switch ((grg_clip_action) callback_action)
	{
	case GRG_CUT:
		gtk_text_buffer_cut_clipboard (entryBuf, clip, TRUE);
		return;

	case GRG_COPY:
		gtk_text_buffer_copy_clipboard (entryBuf, clip);
		return;

	case GRG_PASTE:
		gtk_text_buffer_paste_clipboard (entryBuf, clip, NULL, TRUE);
		return;

	default:
#ifdef MAINTAINER_MODE
		g_assert_not_reached ();
#endif
		break;
	}
}

/**
 * find:
 * @callback_data: TRUE if I have to continue a previous search
 *
 * Search operation.
 */
void
find (GtkWidget *widget, gpointer callback_data)
{
        guint again = GPOINTER_TO_UINT(callback_data);
	static gboolean only_current, case_sens;
	gint found, offset = 0;
	gchar *buf;
	GtkTextIter position;
	GtkTextMark *cursor, *endsel;
        GtkWidget *parent = gtk_widget_get_toplevel(widget);

	/* Save the entry into memory, so if update() is called next it will
	 * be saved. 
	 * */
	sync_entry(); 

	if (!again)
		if (!grg_find_dialog
		    (&needle, &only_current, &case_sens, GTK_WINDOW (parent)))
			return;

	buf = grg_entries_get_Body ();
	if (((current_mode == SIMPLE_ENTRY) && GTK_WIDGET_HAS_FOCUS (simpleSheet))/* ||
		((current_mode == STRUCT_ENTRY) && GTK_WIDGET_HAS_FOCUS (structSheet))*/)
	{
		cursor = gtk_text_buffer_get_mark (entryBuf, "insert");
		gtk_text_buffer_get_iter_at_mark (entryBuf, &position,
						  cursor);
		offset = gtk_text_iter_get_offset (&position);
	}

	while (TRUE)
	{
		found = grg_entries_find (needle, offset, only_current,
					  case_sens);

		if (found >= 0)
		{
			buf = grg_entries_get_Body ();

			g_signal_handler_block (entryBuf, simpleSigID);
			gtk_text_buffer_set_text (entryBuf, buf, -1);
			g_signal_handler_unblock (entryBuf, simpleSigID);

			//to avoid that searching again and again the same text finds
			//the same portion, we set the cursor AFTER the found text
			/* And this time really do it -- Shlomi Fish */
			cursor = gtk_text_buffer_get_mark (entryBuf,
							   "insert");
			gtk_text_buffer_get_iter_at_mark (entryBuf, &position,
							  cursor);
			endsel = gtk_text_buffer_get_mark (entryBuf,
							   "selection_bound");
			gtk_text_iter_set_offset (&position,
						  found +
						  g_utf8_strlen (needle, -1));
			gtk_text_buffer_move_mark (entryBuf, cursor,
						   &position);
			gtk_text_iter_set_offset (&position, found);
			gtk_text_buffer_move_mark (entryBuf, endsel,
						   &position);

			/*
			 * Make sure that the text-view window scrolls to
			 * view the current selection.
			 * */
			gtk_text_view_scroll_mark_onscreen (GTK_TEXT_VIEW (simpleSheet),
				gtk_text_buffer_get_mark (entryBuf,
				"insert"));

			/*
			 * Make sure that the sheet gets focus, this is so
			 * pressing "Find again" consecutively will yield
			 * a second result, as well, as let the user move the
			 * cursor immediately.
			 * */
			gtk_widget_grab_focus (GTK_WIDGET (simpleSheet));

			break;
		}
		else
		{
			if (only_current)
			{
				grg_msg (_
					 ("The text searched could not be found!"),
					 GTK_MESSAGE_ERROR, parent);
				break;
			}
			else
			{
				if (grg_ask_dialog
				    (_("Wrap around?"),
				     _("Text not found. Continue search from beginning?"),
				     FALSE, parent) == GRG_YES)
				{
					grg_entries_first ();
					/* Call update() now, because we changed the page and
					 * sync_entry() may be called later, which will otherwise
					 * cause the first page to be over-rided with the
					 * info in the current page.
					 * */
					update();
					offset = 0;
					continue;
				}
				else
					break;
			}
		}
	}
}
