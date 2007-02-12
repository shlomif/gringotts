/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_menus.h - header file for grg_menus.c
 *  Author: Nicolas Pouillon, Germano Rizzo
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

#ifndef GRG_MENUS_H
#define GRG_MENUS_H

#include <gtk/gtk.h>

// menu File
GtkWidget *bnew, *bopen, *bsave, *bsas, *brev, *bclose, *bquit;

// menu Edit
GtkWidget *badd, *brem, *bcut, *bcop, *bpaste, *bfind, *bfinda, *bpwd, *bpref;

// menu Navigation
GtkWidget *bmfirst, *bmback, *bmfor, *bmlast, *bmind;

// menu Tools
GtkWidget *bwipe;

// menu Help
GtkWidget *babo;

//Makes a menubar, within a handlebox, and returns the GtkWidget
GtkWidget *grg_menu_create (GtkWidget * window);

void grg_menu_update (void);
#endif
