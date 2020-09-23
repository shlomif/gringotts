/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_pwd.h - header file for grg_pwd.c
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

#ifndef GRG_PWD_H
#define GRG_PWD_H

#include <gtk/gtk.h>

/*Asks for a new password, validating it.*/
GRG_KEY grg_new_pwd_dialog (GtkWidget * parent, gboolean *cancelled);

GRG_KEY grg_ask_pwd_dialog (GtkWidget * parent, gboolean *cancelled);

GRG_KEY grg_get_cmdline_key (void);
#endif
