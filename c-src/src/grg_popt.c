/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_popt.c - commandline argument parsing & console-related functionalities
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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <glib.h>
#include <popt.h>

#include "grg_defs.h"
#include "gringotts.h"
#include "grg_pwd.h"
#include "grg_popt.h"
#include "grg_safe.h"
#include "grg_entries.h"
#include "grg_widgets.h"

#include <libgringotts.h>

#ifdef HAVE_TCGETATTR
#include <termios.h>
#endif

static void
dump_content (gchar * fname, gint ennum, gchar * enpage)
{
	GRG_KEY key;
	glong len;
	gint err, fd;
	gchar *txt;

#ifndef HAVE_TCGETATTR
	fprintf (stderr, "%s: %s\n", _("Warning"),
		 _
		 ("it isn't possible to hide password typing; be extremely careful!"));
#endif

	fd = grg_safe_open (fname);

	if (fd < 3)
		report_err (_("The selected file doesn't exists"), 0, 1,
			    NULL);

	if (fd == GRG_OPEN_FILE_IRREGULAR)
		report_err (_("You've selected a directory or a symlink"), 0,
			    1, NULL);

	err = grg_validate_file_direct (gctx, fd);

	switch (err)
	{
	case GRG_OK:
		break;

	case GRG_MEM_ALLOCATION_ERR:
		report_err ("error: malloc failed. Probably this indicates a memory "
		   "problem, such as resource exhaustion. Attempting "
		   "to exit cleanly...",
			    0, 1, NULL);
	
	case GRG_ARGUMENT_ERR:
		report_err (_
			    ("Gringotts internal error. Cannot finish operation."),
			    0, 1, NULL);

	case GRG_READ_MAGIC_ERR:
	case GRG_READ_UNSUPPORTED_VERSION:
		report_err (_
			    ("This file doesn't seem to be a valid Gringotts one!"),
			    0, 1, NULL);

	case GRG_READ_FILE_ERR:
		report_err (_("Uh-oh! I can't read from the file!"), 0, 1,
			    NULL);

	case GRG_READ_CRC_ERR:
	case GRG_READ_COMP_ERR:
		report_err (_("The file appears to be corrupted!"),
			    0, 1, NULL);
#ifdef GRG_READ_TOO_BIG_ERR
	case GRG_READ_TOO_BIG_ERR:
		report_err (_("File is too big"), 0, 1, NULL);
#endif
	default:
		if (err < 0)
			report_err (_
				    ("Gringotts internal error. Cannot finish operation."),
				    0, 1, NULL);
	}

	while (TRUE)
	{
		key = grg_get_cmdline_key ();

		if (!key)
		{
			report_err (_("You must enter a valid password!"), 0,
				    0, NULL);
			continue;
		}

        {
            guchar *unsigned_txt;
		    err = grg_decrypt_file_direct (gctx, key, fd, &unsigned_txt, &len);
            txt = (gchar*)unsigned_txt;
        }

		grg_key_free (gctx, key);

		switch (err)
		{
		case GRG_OK:
			break;

		case GRG_MEM_ALLOCATION_ERR:
			report_err ("error: malloc failed. Probably this indicates a memory "
			   "problem, such as resource exhaustion. Attempting "
			   "to exit cleanly...",
					0, 1, NULL);
		
		case GRG_ARGUMENT_ERR:
			report_err (_("Gringotts internal error. Cannot finish operation."),
					0, 1, NULL);
	
		case GRG_READ_PWD_ERR:
			report_err (_("Wrong password! Re-enter it"), 0, 0,
				    NULL);
			continue;

		case GRG_READ_ENC_INIT_ERR:
			report_err (_
				    ("Problem with libmcrypt, probably a faulty installation"),
				    0, 1, NULL);

		/*just to be sure... */
		default:
			if (err < 0)
				report_err (_("Gringotts internal error. Cannot finish operation."),
					    0, 1, NULL);
		}

		if (!g_utf8_validate (txt, len, NULL))
		{
			GRGFREE (txt, len);
			report_err (_
				    ("Saved data contain invalid UTF-8 chars"),
				    0, 1, NULL);
		}

		break;
	}

	close (fd);

	grg_entries_load_from_string (txt, NULL, FALSE);
	GRGFREE (txt, len);

	grg_entries_print (ennum, enpage);
	grg_entries_free ();
}

static void
exit_freeing_ctx (gint code)
{
	grg_context_free (gctx);
	exit (code);
}

void
grg_parse_argv (gint argc, gchar * argv[], gchar ** filename,
		gboolean * rootCheck)
{
	poptContext optCon;
	gchar *wipe, *etit;
	gint passes, ennum;
	gboolean dump, help, strongRnd;

	struct poptOption optionsTable[] = {
		{"help", 'h', POPT_ARG_NONE, &help, 1, _("shows the help"),
		 NULL},
		{"input-file", 'f', POPT_ARG_STRING, filename, 0,
		 _("specify the input file to open"), _("FILE")},
#ifndef ROOT_FILTER
		{"allow-root", 's', POPT_ARG_NONE, rootCheck, 1,
		 _("allow usage as root -- DANGEROUS"), NULL},
#endif
		{"strong-random", 'R', POPT_ARG_NONE, &strongRnd, 0,
		 _("force use of /dev/random -- slower"), NULL},
		{"dump", 'd', POPT_ARG_NONE, &dump, 0,
		 _("dump the content of a file"), NULL},
		{"entry-num", 0, POPT_ARG_INT, &ennum, 0,
		 _("index of the entry to dump"), _("NUM")},
		{"entry-title", 0, POPT_ARG_STRING, &etit, 0,
		 _("title of the entry to dump"), _("TXT")},
		{"wipe-file", 'w', POPT_ARG_STRING, &wipe, 0,
		 _("securely wipe a file"), _("FILE")},
		{"wipe-passes", 0, POPT_ARG_INT, &passes, 0,
		 _("passes in file wiping"), _("NUM")},
		{NULL, 0, 0, NULL, 0}
	};

	*filename = NULL;
	wipe = NULL;
	etit = NULL;
	passes = 0;
	ennum = -1;
	*rootCheck = FALSE;
	strongRnd = FALSE;
	dump = FALSE;
	help = FALSE;

	optCon = poptGetContext (NULL, argc, (const char **) argv,
				 optionsTable, 0);

	while (poptGetNextOpt (optCon) >= 0) ;

	if (help)
	{
		poptPrintHelp (optCon, stdout, 0);
		poptFreeContext (optCon);
		exit_freeing_ctx (1);
	}

	poptFreeContext (optCon);

	if (strongRnd)
		grg_ctx_set_security_lvl (gctx, GRG_SEC_PARANOIA);

/*quite cerebrotic, I know. The idea is: to ensure that stdin isn't exploitable,
  the best way is to close and reopen it, so that any "abnormal" setting is
  wasted. Since it isn't possible to do this atomically, I check that the former
  file descriptor hasn't been opened in the while by someone that could pretend
  to "be" stdin.*/
	if (!(wipe || dump))
	{
		int canary;

		close (STDIN);
		canary = open ("/dev/null", O_RDONLY);
		if (canary != STDIN)
			exit_freeing_ctx (1);
		return;
	}

/*wipe and dump operations are processed without returning to main() */

/*FIXME this should be in grg_safe.c */
#ifdef HAVE_ISATTY
	if (!isatty (STDIN))
	{
		g_critical ("%s",
			    _
			    ("It isn't possible to redirect data to stdin, as it is a potential security flaw."));
		exit_freeing_ctx (1);
	}
#endif

	if (!grg_security_filter (*rootCheck))
		exit_freeing_ctx (1);

	if (wipe)
	{
		gint res;
		gchar c;

		if (!g_file_test (wipe, G_FILE_TEST_IS_REGULAR))
			report_err (_("The file does not exist"), 0, 1, NULL);

		printf ("%s (y/n)",
			_("Are you sure you want to wipe this file?\n"
			  "Its content will be securely erased, so no\n"
			  "recover is possible."));

		if (passes < 0 || passes > 32)
			passes = 8;

		c = getchar ();

		if (c != 'y' && c != 'Y')
			exit_freeing_ctx (0);

		res = grg_file_shred (wipe, passes);

		if (res < 0)
			report_err (_("File wiping failed"), 0, 1, NULL);

		exit_freeing_ctx (0);
	}

	if (dump)
	{
		if (!*filename)
			report_err (_
				    ("You must specify a file to dump (with the -f switch)"),
				    0, 1, NULL);
		dump_content (*filename, ennum, etit);
		exit_freeing_ctx (0);
	}
}

/* the following code locks and unlocks the console, to hide typed chars.

The code is taken by GnuPG utils/ttyio.c; in this simple implementation, it's
important not to nest them.

The code has been adapted from the GnuPG sources.
Copyright (C) 2002 Free Software Foundation, Inc.
Thanks to them, and thanks to Free Software! :)
*/

#ifdef HAVE_TCGETATTR
static struct termios termsave;
int outty, fd;
#endif

void
block_term (void)
{
#ifdef HAVE_TCGETATTR
	struct termios term;
#ifdef HAVE_ISATTY
	outty = isatty (STDOUT);
#else
	outty = 0;
#endif
	if (!outty)
		fd = open ("/dev/tty", O_RDWR);
	else
		fd = STDOUT;
	tcgetattr (fd, &termsave);
	term = termsave;
	term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
	tcsetattr (fd, TCSAFLUSH, &term);
#endif
}

void
unblock_term (void)
{
#ifdef HAVE_TCGETATTR
	tcsetattr (fd, TCSAFLUSH, &termsave);
	if (!outty)
		close (fd);
#endif
}
