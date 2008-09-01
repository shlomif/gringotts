/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_prefs.c - preferences "bean" and dialog
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
#include <math.h>

#include <gtk/gtk.h>

#include "grg_defs.h"
#include "grg_prefs_io.h"
#include "gringotts.h"
#include "grg_widgets.h"
#include "grg_prefs.h"

#define NEW_RADIO_BUTTON(widget, list, call, value, label, box) \
	widget = gtk_radio_button_new_with_label(list, label); \
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (call), GUINT_TO_POINTER(value)); \
	gtk_box_pack_start(GTK_BOX(box), widget, FALSE, FALSE, GRG_PAD);

#define NEW_LABEL(widget, box, text) \
	widget = gtk_label_new(text); \
	gtk_misc_set_alignment(GTK_MISC(widget), 0, 0); \
	gtk_box_pack_start(GTK_BOX(box), widget, FALSE, FALSE, GRG_PAD);

#define NEW_ROW_SEPARATOR(box) \
	gtk_box_pack_start(GTK_BOX(box), gtk_hseparator_new(), FALSE, FALSE, 0);

static gchar *grg_pref_file = NULL;
static gchar *grg_prefs_editor_font = NULL;

static guchar tmp_pref_crypto;
static guchar tmp_pref_hash;
static guchar tmp_pref_comp;
static guchar tmp_pref_ratio;

static GtkWidget *file_entry;

static gboolean active_flag = FALSE;

/*radio buttons & other things to update */
static GtkWidget *rij1_but, *ser_but, *twof_but, *cast_but, *safer_but;
static GtkWidget *rij2_but, *tdes_but, *loki_but, *sha_but, *ripe_but;
static GtkWidget *zlib_but, *bz_but, *r0_but, *r3_but, *r6_but, *r9_but;
static GtkWidget *crypto_key_lbl, *crypto_block_lbl;
static GtkWidget *bak_check, *over_check, *splash_check, *tray_check, *xpire_check;
static GtkWidget *xpire_spin, *passes_spin, *but_font;
static GtkWidget *cclip_check, *qclip_check;

gboolean grg_prefs_warn4overwrite = TRUE;
gboolean grg_prefs_bak_files = TRUE;
gboolean grg_prefs_splash = TRUE;
gboolean grg_prefs_tray = TRUE;
gboolean grg_prefs_clip_clear_on_close = FALSE;
gboolean grg_prefs_clip_clear_on_quit = TRUE;
gint grg_prefs_xpire = EXP_TIME_DEF;	/*abs(x)= num of days; < 0 = never */
gint grg_prefs_wipe_passes = WIPE_PASSES_DEF;
gint grg_prefs_mainwin_width = -1, grg_prefs_mainwin_height = -1;

gchar *
get_pref_file (void)
{
	if (grg_pref_file)
		return g_strdup (grg_pref_file);
	return NULL;
}

void
set_pref_file (const gchar * newval)
{
	g_free (grg_pref_file);
	grg_pref_file = g_strdup (newval);
}

gchar *
get_pref_font_string (void)
{
	if (grg_prefs_editor_font)
		return g_strdup (grg_prefs_editor_font);
	return NULL;
}

void
set_pref_font_string (const gchar * newval)
{
	g_free (grg_prefs_editor_font);
	grg_prefs_editor_font = g_strdup (newval);
}

void
set_pref_font_string_from_editor (void)
{
	gchar *newval = get_editor_font ();
	set_pref_font_string (newval);
	g_free (newval);
}

static void update_buttons (void);

void
grg_prefs_reset_defaults (void)
{
	grg_ctx_set_crypt_algo (gctx, GRG_SERPENT);
	grg_ctx_set_hash_algo (gctx, GRG_RIPEMD_160);
	grg_ctx_set_comp_algo (gctx, GRG_ZLIB);
	grg_ctx_set_comp_ratio (gctx, GRG_LVL_BEST);
	set_pref_file (NULL);
}

static void
update_entry (void)
{
	if (!active_flag)
		return;
	if (!grg_pref_file)
		gtk_entry_set_text (GTK_ENTRY (file_entry), "");
	else
		gtk_entry_set_text (GTK_ENTRY (file_entry), grg_pref_file);
}

void
grg_prefs_update (void)
{
	update_buttons ();
	update_entry ();
}

static void
reset_values (GtkWidget * parent)
{
	if (grg_load_prefs () != GRG_OK)
	{
		gchar *msg =
			_("Invalid preferences file. Resetting to defaults.");
		grg_msg (msg, GTK_MESSAGE_WARNING, parent);
		grg_prefs_reset_defaults ();
		grg_save_prefs ();
	};
	tmp_pref_crypto = grg_ctx_get_crypt_algo (gctx);
	tmp_pref_hash = grg_ctx_get_hash_algo (gctx);
	tmp_pref_comp = grg_ctx_get_comp_algo (gctx);
	tmp_pref_ratio = grg_ctx_get_comp_ratio (gctx);
	grg_prefs_update ();
}

static void
apply_values (void)
{
	gchar *utf;
	gboolean dirty = FALSE;

	if (grg_ctx_get_crypt_algo(gctx) != tmp_pref_crypto)
	{
		dirty = TRUE;
		grg_ctx_set_crypt_algo (gctx, tmp_pref_crypto);
	}
	if (grg_ctx_get_hash_algo(gctx) != tmp_pref_hash)
	{
		dirty = TRUE;
		grg_ctx_set_hash_algo (gctx, tmp_pref_hash);
	}
	if (grg_ctx_get_comp_algo(gctx) != tmp_pref_comp)
	{
		dirty = TRUE;
		grg_ctx_set_comp_algo (gctx, tmp_pref_comp);
	}
	if (grg_ctx_get_comp_ratio(gctx) != tmp_pref_ratio)
	{
		dirty = TRUE;
		grg_ctx_set_comp_ratio (gctx, tmp_pref_ratio);
	}

	set_pref_file (gtk_entry_get_text (GTK_ENTRY (file_entry)));
	utf = g_filename_from_utf8 (grg_pref_file, -1, NULL, NULL, NULL);
	if (!g_file_test (utf, G_FILE_TEST_IS_REGULAR))
	{
		grg_prefs_free ();
		gtk_entry_set_text (GTK_ENTRY (file_entry), "");
	}
	g_free (utf);

	set_pref_font_string (pango_font_description_to_string
			      (pango_context_get_font_description
			       (gtk_widget_get_pango_context
				(gtk_bin_get_child (GTK_BIN (but_font))))));
	set_editor_font (grg_prefs_editor_font);

	if (dirty)
		update_saveable (GRG_SAVE_ACTIVE);

	/* unconditionally save prefs */
	grg_save_prefs ();
}

static void
update_crypto_label (void)
{
	gchar *lbltxt;
	guint key, block;

	block = grg_get_block_size_static (tmp_pref_crypto);
	key = grg_get_key_size_static (tmp_pref_crypto);
	lbltxt = g_strdup_printf (_(" Block size: %d bits"), block * 8);
	gtk_label_set_text (GTK_LABEL (crypto_block_lbl), lbltxt);
	g_free (lbltxt);
	lbltxt = g_strdup_printf (_(" Key length: %d bits"), key * 8);
	gtk_label_set_text (GTK_LABEL (crypto_key_lbl), lbltxt);
	g_free (lbltxt);
}

void
grg_prefs_free (void)
{
	g_free (grg_pref_file);
	grg_pref_file = NULL;
}

static void
modify_crypto (GtkWidget * data, gpointer value)
{
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data)))
		return;

	tmp_pref_crypto = GPOINTER_TO_UINT (value);
	update_crypto_label ();
}

static void
modify_hash (GtkWidget * data, gpointer value)
{
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data)))
		return;

	tmp_pref_hash = GPOINTER_TO_UINT (value);
}

static void
modify_comp (GtkWidget * data, gpointer value)
{
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data)))
		return;

	tmp_pref_comp = GPOINTER_TO_UINT (value);
}

static void
modify_ratio (GtkWidget * data, gpointer value)
{
	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data)))
		return;

	tmp_pref_ratio = GPOINTER_TO_UINT (value);
}

static void
modify_over (GtkWidget * data, gpointer value)
{
	grg_prefs_warn4overwrite =
		gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data));
}


static void
modify_bak (GtkWidget * data, gpointer value)
{
	grg_prefs_bak_files =
		gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data));
}

static void
modify_splash (GtkWidget * data, gpointer value)
{
	grg_prefs_splash =
		gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data));
}

static void
modify_tray (GtkWidget * data, gpointer value)
{
	grg_prefs_tray =
		gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data));
}

static void
modify_cclip (GtkWidget * data, gpointer value)
{
	grg_prefs_clip_clear_on_close =
		gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data));
	gtk_widget_set_sensitive (qclip_check,
				  !grg_prefs_clip_clear_on_close);
}

static void
modify_qclip (GtkWidget * data, gpointer value)
{
	grg_prefs_clip_clear_on_quit =
		gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data));
}

static void
modify_xpire (GtkWidget * data, gpointer value)
{
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data)))
		grg_prefs_xpire = abs (grg_prefs_xpire);
	else
		grg_prefs_xpire = 0 - abs (grg_prefs_xpire);

	gtk_widget_set_sensitive (GTK_WIDGET (value),
				  gtk_toggle_button_get_active
				  (GTK_TOGGLE_BUTTON (data)));
}

static void
modify_xpin (GtkWidget * data, gpointer value)
{
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (value)))
		grg_prefs_xpire =
			gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON
							  (data));
	else
		grg_prefs_xpire =
			0 -
			gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON
							  (data));

	gtk_widget_set_sensitive (GTK_WIDGET (data),
				  gtk_toggle_button_get_active
				  (GTK_TOGGLE_BUTTON (value)));
}

static void
modify_passes (GtkWidget * data, gpointer value)
{
	grg_prefs_wipe_passes =
		gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (data));
}

static void
modify_font (GtkWidget * data, gpointer value)
{
	GtkWidget *font_selector;
#if 0
    GtkWidget *wait;
#endif
	gint response;
#if 0
	gchar *selection = NULL;
#endif
	PangoFontDescription *pfd;

	font_selector = gtk_font_selection_dialog_new ("Select a font...");
	gtk_window_set_transient_for (GTK_WINDOW (font_selector),
				      GTK_WINDOW (value));
	gtk_font_selection_dialog_set_font_name (GTK_FONT_SELECTION_DIALOG
						 (font_selector),
						 grg_prefs_editor_font);
	gtk_widget_show (font_selector);
	response = gtk_dialog_run (GTK_DIALOG (font_selector));
	if (response == GTK_RESPONSE_OK)
	{
		pfd = pango_font_description_from_string
			(gtk_font_selection_dialog_get_font_name
			 (GTK_FONT_SELECTION_DIALOG (font_selector)));
		gtk_widget_modify_font (gtk_bin_get_child
					(GTK_BIN (but_font)), pfd);
		pango_font_description_free (pfd);
	}

	gtk_widget_destroy (font_selector);
}

static void
meta_open_startup_file (GtkWidget * wid, gpointer value)
{
    GtkWidget *file_chooser;
	gint response;

    file_chooser = gtk_file_chooser_dialog_new (_("Select file..."),
            GTK_WINDOW(value),
            GTK_FILE_CHOOSER_ACTION_OPEN,
            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
            GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
            NULL);

	response = gtk_dialog_run (GTK_DIALOG (file_chooser));

    if (response == GTK_RESPONSE_ACCEPT)
	{
        gchar * filename;
        filename = gtk_file_chooser_get_filename (
                GTK_FILE_CHOOSER (file_chooser)
                );

		gchar *utf =
			g_filename_to_utf8 (filename, -1, NULL, NULL, NULL);
        g_free (filename);
		gtk_entry_set_text (GTK_ENTRY (file_entry), utf);
		g_free (utf);
	}

    gtk_widget_destroy (file_chooser);
}

static void
clear_file (void)
{
	gtk_entry_set_text (GTK_ENTRY (file_entry), "");
}

void
grg_pref_dialog (GtkWidget * parent)
{
	GtkWidget *prefs, *notebook, *tab1, *tab2, *tab3;
	GtkWidget *frame1, *frame2, *frame3;
	GtkWidget *crypt_box, *hash_box, *comp_box;
	GtkWidget *frame_font;
	GtkWidget *frame_file, *but_file, *box_file, *but_file_clear;
	GtkWidget *frame_save, *box_save;
	GtkWidget *frame_misc, *box_misc;
	GtkWidget *frame_xpire, *box_xpire, *xpire_lbl;
	GtkWidget *frame_passes, *box_passes, *lbl_passes;
	GtkWidget *frame_clip, *box_clip;

	PangoFontDescription *fdesc;

	if (active_flag)
		return;

	prefs = gtk_dialog_new_with_buttons (_("Preferences"),
					     GTK_WINDOW (parent),
					     GTK_DIALOG_DESTROY_WITH_PARENT,
					     GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					     GTK_STOCK_APPLY, GTK_RESPONSE_APPLY,
					     GTK_STOCK_OK, GTK_RESPONSE_OK,
					     NULL);

	/*first page: algorithms */
	tab1 = gtk_table_new (3, 2, FALSE);

	frame1 = gtk_frame_new (_("Encryption"));
	gtk_table_attach_defaults (GTK_TABLE (tab1), frame1, 0, 1, 0, 3);

	crypt_box = gtk_vbox_new (FALSE, GRG_PAD);
	gtk_container_add (GTK_CONTAINER (frame1), crypt_box);

	NEW_RADIO_BUTTON (rij1_but, NULL, modify_crypto, GRG_AES,
			  "AES (Rijndael 128)", crypt_box);
	NEW_RADIO_BUTTON (ser_but,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (rij1_but)),
			  modify_crypto, GRG_SERPENT, "Serpent", crypt_box);
	NEW_RADIO_BUTTON (twof_but,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (rij1_but)),
			  modify_crypto, GRG_TWOFISH, "Twofish", crypt_box);
	NEW_RADIO_BUTTON (cast_but,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (rij1_but)),
			  modify_crypto, GRG_CAST_256, "Cast 256", crypt_box);
	NEW_RADIO_BUTTON (safer_but,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (rij1_but)),
			  modify_crypto, GRG_SAFERPLUS, "Safer+", crypt_box);
	NEW_RADIO_BUTTON (loki_but,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (rij1_but)),
			  modify_crypto, GRG_LOKI97, "Loki97", crypt_box);
	NEW_RADIO_BUTTON (tdes_but,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (rij1_but)),
			  modify_crypto, GRG_3DES, "3-DES", crypt_box);
	NEW_RADIO_BUTTON (rij2_but,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (rij1_but)),
			  modify_crypto, GRG_RIJNDAEL_256, "Rijndael 256",
			  crypt_box);

	NEW_ROW_SEPARATOR (crypt_box);

	NEW_LABEL (crypto_block_lbl, crypt_box, "");
	NEW_LABEL (crypto_key_lbl, crypt_box, "");

	update_crypto_label ();

	frame2 = gtk_frame_new (_("Hashing"));
	gtk_table_attach_defaults (GTK_TABLE (tab1), frame2, 1, 2, 0, 1);

	hash_box = gtk_vbox_new (FALSE, GRG_PAD);
	gtk_container_add (GTK_CONTAINER (frame2), hash_box);

	NEW_RADIO_BUTTON (sha_but, NULL, modify_hash, GRG_SHA1, "SHA1",
			  hash_box);
	NEW_RADIO_BUTTON (ripe_but,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (sha_but)), modify_hash,
			  GRG_RIPEMD_160, "RIPEMD 160", hash_box);

	frame3 = gtk_frame_new (_("Compression"));
	gtk_table_attach_defaults (GTK_TABLE (tab1), frame3, 1, 2, 1, 2);

	comp_box = gtk_vbox_new (FALSE, GRG_PAD);
	gtk_container_add (GTK_CONTAINER (frame3), comp_box);

	NEW_RADIO_BUTTON (zlib_but, NULL, modify_comp, GRG_ZLIB, "ZLib",
			  comp_box);
	NEW_RADIO_BUTTON (bz_but,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (zlib_but)),
			  modify_comp, GRG_BZIP, "BZip2", comp_box);

	NEW_ROW_SEPARATOR (comp_box);

	NEW_RADIO_BUTTON (r0_but, NULL, modify_ratio, GRG_LVL_NONE, _("None"),
			  comp_box);
	NEW_RADIO_BUTTON (r3_but,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (r0_but)), modify_ratio,
			  GRG_LVL_FAST, _("Fast"), comp_box);
	NEW_RADIO_BUTTON (r6_but,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (r0_but)), modify_ratio,
			  GRG_LVL_GOOD, _("Good"), comp_box);
	NEW_RADIO_BUTTON (r9_but,
			  gtk_radio_button_get_group (GTK_RADIO_BUTTON
						      (r0_but)), modify_ratio,
			  GRG_LVL_BEST, _("Best"), comp_box);

	notebook = gtk_notebook_new ();
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), tab1,
				  gtk_label_new (_("Algorithms")));
	gtk_box_pack_start (GTK_BOX (GTK_DIALOG (prefs)->vbox), notebook,
			    TRUE, TRUE, GRG_PAD);

	/*second page: General options */
	tab2 = gtk_vbox_new (FALSE, GRG_PAD);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), tab2,
				  gtk_label_new (_("General options")));

	frame_font = gtk_frame_new (_("Editor font"));
	gtk_box_pack_start (GTK_BOX (tab2), frame_font, FALSE, TRUE, 1);

	but_font =
		gtk_button_new_with_label (_
					   ("Click to change the editor font"));
	gtk_container_add (GTK_CONTAINER (frame_font), but_font);

	fdesc = pango_font_description_from_string (grg_prefs_editor_font);
	gtk_widget_modify_font (but_font, fdesc);
	pango_font_description_free (fdesc);

	g_signal_connect (G_OBJECT (but_font), "clicked",
			  G_CALLBACK (modify_font), prefs);

	frame_misc = gtk_frame_new (_("Decorations"));
	gtk_box_pack_start (GTK_BOX (tab2), frame_misc, FALSE, TRUE, 1);

	box_misc = gtk_vbox_new (FALSE, GRG_PAD);
	gtk_container_add (GTK_CONTAINER (frame_misc), box_misc);

	NEW_ROW_SEPARATOR (tab2);

	splash_check = gtk_check_button_new_with_label (_("Splash screen"));
	g_signal_connect (G_OBJECT (splash_check), "toggled",
			  G_CALLBACK (modify_splash), NULL);
	gtk_box_pack_start (GTK_BOX (box_misc), splash_check, FALSE, TRUE, 1);


	NEW_ROW_SEPARATOR (tab2);

	tray_check = gtk_check_button_new_with_label (_("Tray-Icon (Needs Gringotts restart to take affect)"));
	g_signal_connect (G_OBJECT (tray_check), "toggled",
			G_CALLBACK (modify_tray), NULL);
	gtk_box_pack_start (GTK_BOX (box_misc), tray_check, FALSE, TRUE, 1);

	frame_file = gtk_frame_new (_("File to open at startup"));
	gtk_box_pack_start (GTK_BOX (tab2), frame_file, FALSE, TRUE, 1);

	box_file = gtk_hbox_new (FALSE, GRG_PAD);
	gtk_container_add (GTK_CONTAINER (frame_file), box_file);

	file_entry = gtk_entry_new ();
	gtk_box_pack_start (GTK_BOX (box_file), file_entry, FALSE, TRUE, 1);
	but_file = gtk_button_new_from_stock (GTK_STOCK_OPEN);
	gtk_box_pack_start (GTK_BOX (box_file), but_file, FALSE, TRUE, 1);
	g_signal_connect (G_OBJECT (but_file), "clicked",
			  G_CALLBACK (meta_open_startup_file),
			  (gpointer) prefs);
	but_file_clear = gtk_button_new_from_stock (GTK_STOCK_CLEAR);
	gtk_box_pack_start (GTK_BOX (box_file), but_file_clear, FALSE, TRUE,
			    1);
	g_signal_connect (G_OBJECT (but_file_clear), "clicked",
			  G_CALLBACK (clear_file), NULL);

	frame_save = gtk_frame_new (_("File saving"));
	gtk_box_pack_start (GTK_BOX (tab2), frame_save, FALSE, TRUE, 1);

	box_save = gtk_vbox_new (FALSE, GRG_PAD);
	gtk_container_add (GTK_CONTAINER (frame_save), box_save);

	bak_check =
		gtk_check_button_new_with_label (_("Make backups of files"));
	g_signal_connect (G_OBJECT (bak_check), "toggled",
			  G_CALLBACK (modify_bak), NULL);
	gtk_box_pack_start (GTK_BOX (box_save), bak_check, FALSE, TRUE, 1);
	over_check =
		gtk_check_button_new_with_label (_
						 ("Ask when overwriting files"));
	g_signal_connect (G_OBJECT (over_check), "toggled",
			  G_CALLBACK (modify_over), NULL);
	gtk_box_pack_start (GTK_BOX (box_save), over_check, FALSE, TRUE, 1);

	/*third page: Security */
	tab3 = gtk_vbox_new (FALSE, GRG_PAD);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), tab3,
				  gtk_label_new (_("Security")));

	frame_xpire = gtk_frame_new (_("Password expiration"));
	gtk_box_pack_start (GTK_BOX (tab3), frame_xpire, FALSE, TRUE, 1);

	box_xpire = gtk_hbox_new (FALSE, GRG_PAD);
	gtk_container_add (GTK_CONTAINER (frame_xpire), box_xpire);

	xpire_check =
		gtk_check_button_new_with_label (_("Password expires in"));
	xpire_spin =
		gtk_spin_button_new_with_range (EXP_TIME_MIN, EXP_TIME_MAX,
						1);
	xpire_lbl = gtk_label_new (_("days"));

	g_signal_connect (G_OBJECT (xpire_check), "toggled",
			  G_CALLBACK (modify_xpire), xpire_spin);
	g_signal_connect (G_OBJECT (xpire_spin), "value-changed",
			  G_CALLBACK (modify_xpin), xpire_check);

	gtk_box_pack_start (GTK_BOX (box_xpire), xpire_check, FALSE, TRUE, 1);
	gtk_box_pack_start (GTK_BOX (box_xpire), xpire_spin, FALSE, TRUE, 1);
	gtk_box_pack_start (GTK_BOX (box_xpire), xpire_lbl, FALSE, TRUE, 1);

	/*this means "passes in wiping a file", not "wipe the passes" :) */
	frame_passes = gtk_frame_new (_("Wipe passes"));
	gtk_box_pack_start (GTK_BOX (tab3), frame_passes, FALSE, TRUE, 1);

	box_passes = gtk_hbox_new (FALSE, GRG_PAD);
	gtk_container_add (GTK_CONTAINER (frame_passes), box_passes);

	lbl_passes = gtk_label_new (_("Number of overwritings with random\n"
				      "data, when wiping a file:"));
	gtk_box_pack_start (GTK_BOX (box_passes), lbl_passes, FALSE, TRUE, 1);

	passes_spin =
		gtk_spin_button_new_with_range (WIPE_PASSES_MIN,
						WIPE_PASSES_MAX, 1);
	gtk_box_pack_start (GTK_BOX (box_passes), passes_spin, FALSE, TRUE,
			    1);

	g_signal_connect (G_OBJECT (passes_spin), "value-changed",
			  G_CALLBACK (modify_passes), NULL);

	frame_clip = gtk_frame_new (_("Clipboard"));
	gtk_box_pack_start (GTK_BOX (tab3), frame_clip, FALSE, TRUE, 1);

	box_clip = gtk_vbox_new (FALSE, GRG_PAD);
	gtk_container_add (GTK_CONTAINER (frame_clip), box_clip);

	cclip_check =
		gtk_check_button_new_with_label (_
						 ("Clear clipboard on closing file"));
	g_signal_connect (G_OBJECT (cclip_check), "toggled",
			  G_CALLBACK (modify_cclip), NULL);
	gtk_box_pack_start (GTK_BOX (box_clip), cclip_check, FALSE, TRUE, 1);

	qclip_check =
		gtk_check_button_new_with_label (_
						 ("Clear clipboard on exit"));
	g_signal_connect (G_OBJECT (qclip_check), "toggled",
			  G_CALLBACK (modify_qclip), NULL);
	gtk_box_pack_start (GTK_BOX (box_clip), qclip_check, FALSE, TRUE, 1);

	/*end of last tab */
	active_flag = TRUE;
	reset_values (prefs);
	update_buttons ();

	gtk_widget_show_all (prefs);

	while (TRUE)
	{
		gboolean exit = TRUE;
		gint response = gtk_dialog_run (GTK_DIALOG (prefs));

		switch (response)
		{
		case GTK_RESPONSE_OK:
			apply_values ();
			break;
		case GTK_RESPONSE_APPLY:
			apply_values ();
			exit = FALSE;
			break;
		default:
			break;
		}

		if (exit)
		{
			gtk_widget_destroy (prefs);
			active_flag = FALSE;
			break;
		}
	}
}

static void
update_buttons (void)
{
	PangoFontDescription *pfd;

	if (!active_flag)
		return;

	switch (tmp_pref_crypto)
	{
	case GRG_AES:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (rij1_but),
					      TRUE);
		break;
	case GRG_SERPENT:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (ser_but),
					      TRUE);
		break;
	case GRG_TWOFISH:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (twof_but),
					      TRUE);
		break;
	case GRG_CAST_256:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (cast_but),
					      TRUE);
		break;
	case GRG_SAFERPLUS:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (safer_but),
					      TRUE);
		break;
	case GRG_LOKI97:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (loki_but),
					      TRUE);
		break;
	case GRG_3DES:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (tdes_but),
					      TRUE);
		break;
	case GRG_RIJNDAEL_256:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (rij2_but),
					      TRUE);
		break;
	default:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (ser_but),
					      TRUE);
		tmp_pref_crypto = GRG_SERPENT;
	}

	update_crypto_label ();

	switch (tmp_pref_hash)
	{
	case GRG_SHA1:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (sha_but),
					      TRUE);
		break;
	case GRG_RIPEMD_160:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (ripe_but),
					      TRUE);
		break;
	default:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (ripe_but),
					      TRUE);
		tmp_pref_hash = GRG_RIPEMD_160;
	}

	switch (tmp_pref_comp)
	{
	case GRG_ZLIB:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (zlib_but),
					      TRUE);
		break;
	case GRG_BZIP:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (bz_but),
					      TRUE);
		break;
	default:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (zlib_but),
					      TRUE);
		tmp_pref_comp = GRG_ZLIB;
	}

	switch (tmp_pref_ratio)
	{
	case GRG_LVL_NONE:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (r0_but),
					      TRUE);
		break;
	case GRG_LVL_FAST:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (r3_but),
					      TRUE);
		break;
	case GRG_LVL_GOOD:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (r6_but),
					      TRUE);
		break;
	case GRG_LVL_BEST:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (r9_but),
					      TRUE);
		break;
	default:
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (r9_but),
					      TRUE);
		tmp_pref_ratio = GRG_LVL_BEST;
	}

	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (xpire_check),
				      grg_prefs_xpire > 0);
	gtk_spin_button_set_value (GTK_SPIN_BUTTON (xpire_spin),
				   abs (grg_prefs_xpire));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (bak_check),
				      grg_prefs_bak_files);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (over_check),
				      grg_prefs_warn4overwrite);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (splash_check),
				      grg_prefs_splash);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (tray_check),
					grg_prefs_tray);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (cclip_check),
				      grg_prefs_clip_clear_on_close);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (qclip_check),
				      grg_prefs_clip_clear_on_quit);
	gtk_spin_button_set_value (GTK_SPIN_BUTTON (passes_spin),
				   abs (grg_prefs_wipe_passes));

	gtk_widget_set_sensitive (qclip_check,
				  !grg_prefs_clip_clear_on_close);

	pfd = pango_font_description_from_string (grg_prefs_editor_font);
	gtk_widget_modify_font (gtk_bin_get_child (GTK_BIN (but_font)), pfd);
	pango_font_description_free (pfd);
}
