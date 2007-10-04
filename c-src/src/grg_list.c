/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_list.c - widget used to display the list of entries
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

#include "gringotts.h"
#include "grg_entries.h"
#include "grg_defs.h"
#include "grg_pix.h"
#include "grg_widgets.h"

enum
{
	COL_INDEX,
	COL_ID,
	NUM_ATT,
	NUM_COL
};

static GtkWidget *treeview;
static GtkTreeModel *model;

/**
 * create_model:
 *
 * Creates the model for the GTK list widget
 *
 * Returns: a GtkTreeModel with the desired model
 */
static GtkTreeModel *
create_model (void)
{
	gint i = 0, pos = grg_entries_position (), max = grg_entries_n_el ();
	GtkListStore *store;
	GtkTreeIter iter;

	store = gtk_list_store_new (NUM_COL, G_TYPE_UINT, G_TYPE_STRING,
				    G_TYPE_STRING);

	grg_entries_first ();
	for (i = 0; i < max; i++, grg_entries_next ())
	{
		guint nat = grg_entries_n_att ();
		gchar *snat =
			(nat == 0) ? g_strdup ("-") : g_strdup_printf ("%d",
								       nat);

		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter,
				    COL_INDEX, i + 1,
				    COL_ID, grg_entries_get_ID (),
				    NUM_ATT, snat, -1);

		g_free (snat);
	}

	grg_entries_nth (pos);

	return GTK_TREE_MODEL (store);
}

/**
 * add_columns:
 * @treeview: the GtkTreeView to add the column to
 *
 * Adds a column to a GtkTreeView.
 */
static void
add_columns (GtkTreeView * treeview)
{
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	GtkWidget *img_att;
	GdkPixbuf *pix;

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes (_(" Index "),
							   renderer,
							   "text", COL_INDEX,
							   NULL);
	gtk_tree_view_column_set_alignment (column, (gfloat) 0.5);
	gtk_tree_view_append_column (treeview, column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes (_(" Title "),
							   renderer,
							   "text", COL_ID,
							   NULL);
	gtk_tree_view_column_set_alignment (column, (gfloat) 0.5);
	gtk_tree_view_append_column (treeview, column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new ();

	pix = gdk_pixbuf_new_from_xpm_data (clip_xpm);
	img_att = gtk_image_new_from_pixbuf (pix);
	gtk_misc_set_alignment (GTK_MISC (img_att), (gfloat) 0.5,
				(gfloat) 0.0);
	g_object_unref (G_OBJECT (pix));

	gtk_tree_view_column_set_widget (column, img_att);
	g_object_set (G_OBJECT (renderer), "xalign", (gfloat) 0.5, NULL);
	//needed at least in GTK 2.0.6, anyways doing it seems stupid 2 me
	gtk_widget_show (img_att);
	gtk_tree_view_column_pack_start (column, renderer, TRUE);
	gtk_tree_view_column_add_attribute (column, renderer, "text",
					    NUM_ATT);

	gtk_tree_view_column_set_alignment (column, (gfloat) 0.5);

	gtk_tree_view_append_column (treeview, column);
}

/**
 * get_sel_row_num:
 *
 * Gets the number of the selected row
 *
 * returns: a gint with the number
 */
static gint
get_sel_row_num (void)
{
	gint ret;
	GtkTreeSelection *gts =
		gtk_tree_view_get_selection (GTK_TREE_VIEW (treeview));

	GtkTreeIter i;
	if (!gtk_tree_selection_get_selected (gts, NULL, &i))
		return 0;

	gtk_tree_model_get (model, &i, 0, &ret, -1);

	return ret - 1;
}

/**
 * move_row:
 * @unused: unused... :-)
 * @upwards: a pointer encapsulating TRUE if the row has to be moved upwards, else FALSE
 *
 * Shifts a row upwards or downwards
 */
static void
move_row (gpointer unused, gpointer upwards)
{
	gint pos = get_sel_row_num ();
	gboolean up = GPOINTER_TO_INT (upwards);
	GtkTreePath *path = gtk_tree_path_new ();

	if (pos == (up ? 0 : (grg_entries_n_el () - 1)))
		return;
	grg_entries_nth (pos);

	if (up)
		grg_entries_raise ();
	else
		grg_entries_sink ();

	model = create_model ();
	gtk_tree_view_set_model (GTK_TREE_VIEW (treeview), model);
	gtk_tree_path_append_index (path, pos + (up ? -1 : 1));
	gtk_tree_view_set_cursor (GTK_TREE_VIEW (treeview), path, NULL,
				  FALSE);
	gtk_tree_path_free (path);
	update_saveable (GRG_SAVE_ACTIVE);
}

/**
 * double_click:
 *
 * Manages a double click event
 */
static gboolean
double_click (GtkWidget * widget, GdkEventButton * event, gpointer user_data)
{
	gboolean ret = (event->type == GDK_2BUTTON_PRESS);
	if (ret)
		gtk_dialog_response (GTK_DIALOG (user_data), GTK_RESPONSE_OK);
	return ret;
}

/**
 * grg_list_run:
 *
 * Creates, manages and displays a dialog with the entry list
 */
void
grg_list_run (void)
{
	GtkWidget *dialog, *sw, *tbar, *hbox, *bup, *bdown;
	GtkTreePath *path = gtk_tree_path_new ();
	guint res;

	dialog = gtk_dialog_new_with_buttons (_("Index of entries"), NULL,
					      GTK_DIALOG_MODAL, GTK_STOCK_OK,
					      GTK_RESPONSE_OK, NULL);
	gtk_container_set_border_width (GTK_CONTAINER (dialog), GRG_PAD);
	gtk_box_set_spacing (GTK_BOX (GTK_DIALOG (dialog)->vbox), GRG_PAD);

	sw = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (sw),
					     GTK_SHADOW_ETCHED_IN);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (sw),
					GTK_POLICY_NEVER,
					GTK_POLICY_AUTOMATIC);

	model = create_model ();

	treeview = gtk_tree_view_new_with_model (model);
	gtk_tree_view_set_rules_hint (GTK_TREE_VIEW (treeview), TRUE);
	gtk_tree_view_set_search_column (GTK_TREE_VIEW (treeview), COL_ID);
	g_signal_connect (G_OBJECT (treeview), "button-press-event",
			  G_CALLBACK (double_click), (gpointer) dialog);
	g_object_unref (G_OBJECT (model));

	gtk_container_add (GTK_CONTAINER (sw), treeview);

	add_columns (GTK_TREE_VIEW (treeview));

	tbar = gtk_toolbar_new ();
	gtk_toolbar_set_orientation (GTK_TOOLBAR (tbar),
				     GTK_ORIENTATION_VERTICAL);
#if 0
	gtk_toolbar_set_icon_size (GTK_TOOLBAR (tbar),
				   GTK_ICON_SIZE_LARGE_TOOLBAR);
#endif
	bup = grg_toolbar_insert_stock (GTK_TOOLBAR (tbar), GTK_STOCK_GO_UP,
					_("Move up"),
					(GtkSignalFunc) move_row,
					GINT_TO_POINTER (TRUE), -1);
	bdown = grg_toolbar_insert_stock (GTK_TOOLBAR (tbar),
					  GTK_STOCK_GO_DOWN, _("Move down"),
					  (GtkSignalFunc) move_row,
					  GINT_TO_POINTER (FALSE), -1);

	hbox = gtk_hbox_new (FALSE, GRG_PAD);
	gtk_box_set_homogeneous (GTK_BOX (hbox), FALSE);
	gtk_box_pack_start (GTK_BOX (hbox), tbar, FALSE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (hbox), sw, TRUE, TRUE, 0);

	gtk_box_pack_start (GTK_BOX (GTK_DIALOG (dialog)->vbox), hbox, TRUE,
			    TRUE, 0);
	gtk_window_set_default_size (GTK_WINDOW (dialog), 180, 250);

	gtk_tree_path_append_index (path, grg_entries_position ());
	gtk_tree_view_set_cursor (GTK_TREE_VIEW (treeview), path, NULL,
				  FALSE);
	gtk_tree_path_free (path);

	gtk_widget_show_all (dialog);
	res = gtk_dialog_run (GTK_DIALOG (dialog));

	if (res == GTK_RESPONSE_OK)
		grg_entries_nth (get_sel_row_num ());
	else
		grg_entries_nth (0);

	gtk_widget_destroy (dialog);
}
