/*  Gringotts - a small utility to safe-keep sensitive data
 *  (c) 2002, Germano Rizzo <mano78@users.sourceforge.net>
 *
 *  grg_safe.c - security management
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

#define __USE_GNU		// to use the global variable "environ" in stdlib.h

#include <gtk/gtk.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <mcrypt.h>

#include "grg_defs.h"
#include "gringotts.h"
#include "grg_safe.h"
#include "grg_widgets.h"
#include "grg_pix.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <locale.h>
#include <sys/mman.h>
#ifdef HAVE_SYS_FSUID_H
#include <sys/fsuid.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#ifdef linux
#include <sys/utsname.h>
#endif
#include <sys/stat.h>
#include <stdio.h>

#define GRG_SAFE			0
#define GRG_SLIGHTLY_UNSAFE	1
#define GRG_UNSAFE			2

static gboolean mem_safe = FALSE,
                ptrace_safe = FALSE;
static gint     safety_level = GRG_SAFE;

#ifdef linux
/* check if current kernel release X.Y.Z is greater or equal than a.b.c */
static gboolean grg_kver_ge (int a, int b, int c) {
    struct utsname uval;
    char *s1, *s2, *s3;
    char* release;
    int X, Y, Z;
    uname(&uval);
    release = uval.release;
    s1 = strsep(&release, ".");
    s2 = strsep(&release, ".");
    s3 = strsep(&release, ".");
    if (s1==NULL || s2==NULL || s3==NULL) {
        /* unknown kernel version, assume FALSE */
        return FALSE;
    }
    X = atoi(s1);
    Y = atoi(s2);
    Z = atoi(s3);
    return 
        ((X > a) ||
            (
                (X ==a) &&
                (
                    (Y > b) ||
                    ((Y == b) && (Z >= c))
                )
            )
        );
}
#endif

gboolean
grg_mlockall_and_drop_root_privileges(void)
{
    // drop eventual group root privileges
    setgid(getgid());
    setgid(getgid());		// twice for counter "saved IDs", cfr.
				// Secure Programming HowTo
#ifdef HAVE_SYS_FSUID_H
    setfsgid(getgid());
    setfsgid(getgid());
#endif

    if (!geteuid())
	// the process is (ev. SUID) root. I can mlockall() the memory in
	// order to avoid swapping.
    {
#ifdef HAVE_MLOCKALL
#ifdef linux
        if (grg_kver_ge(2, 6, 9)) {
            // since Linux 2.6.9, the memlock amount of unprivileged processes
            // is limited to the soft limit of RLIMIT_MEMLOCK
            // Check if there is at least 50000 KB available (which should be
            // ok for most usages). Else there can be nasty segmentation
            // faults due to failing malloc() calls and missing NULL checks in
            // unrelated libraries (eg. libX11 functions).
            struct rlimit rl;
            gint res = getrlimit(RLIMIT_MEMLOCK, &rl);
            gint minbytes = 50000*1024;
            if (res) {
                g_critical(_("Cannot get MEMLOCK resource limit: %s"),
                           strerror(errno));
                return FALSE;
            }
            if (rl.rlim_cur < minbytes) {
                g_critical(_("Increase the memory locking limit to at least "
                             "%d bytes. Current limit: %d bytes.\n"
                             "See /usr/share/doc/gringotts/README.Debian for directions."),
                           minbytes, rl.rlim_cur);
                return FALSE;
            }
        }
#endif
	gint res = mlockall(MCL_CURRENT | MCL_FUTURE);

	if (res) {
	    g_critical("%s",
		       _
		       ("The process is setuid root, but I can't lock memory paging"));
	    return FALSE;
	} else
	    mem_safe = TRUE;
#endif

	// drop root privileges
	setuid(getuid());
	setuid(getuid());
#ifdef HAVE_SYS_FSUID_H
	setfsuid(getuid());
	setfsuid(getuid());
#endif

#ifdef HAVE_SYS_FSUID_H
	if (getuid() && (!setuid(0) || !setfsuid(0)))
#else
	if (getuid() && !setuid(0))
#endif
	{
	    g_critical("%s",
		       _
		       ("Cannot drop root user privileges. Someone is hacking this process. I cannot go on"));
	    return FALSE;
	}
	ptrace_safe = TRUE;
    }
#ifdef HAVE_SYS_FSUID_H
    if (getgid() && (!setgid(0) || !setfsgid(0)))
#else
    if (getgid() && !setgid(0))
#endif
    {
	g_critical("%s",
		   _
		   ("Cannot drop root group privileges. Someone is hacking this process. I cannot go on"));
	return FALSE;
    }

    return TRUE;
}

static void
change_sec_level(gint newval)
{
    if (safety_level < newval)
	safety_level = newval;
}

static void
grg_compile_re (regex_t* regex, const char* pat, int cflags)
{
    int err = regcomp(regex, pat, cflags);
    if (err) {
        char errbuf[1024];
        regerror(err, regex, errbuf, 1024);
        g_critical("pattern `%s': %s", pat, errbuf);
        emergency_quit();
    }
}

gboolean
grg_security_filter(gboolean rootCheck)
{
    gint            canary;
    struct rlimit  *rl;
#ifdef ENV_CHECK
    regex_t regexp;
    gchar          *display,
                   *xauth;
#endif
    gchar          *lang;
    gchar          *htab;

    if (!rootCheck && (!getuid() || !geteuid()))
	// forbid usage as root user
    {
#ifdef ROOT_FILTER
	g_critical("%s %s",
		   _
		   ("For security reasons, you cannot run Gringotts as root user."),
		   _
		   ("Try to compile with --disable-root-filter in ./configure"));
#else
	g_critical("%s %s",
		   _
		   ("For security reasons, you cannot run Gringotts as root user."),
		   _("Try using -s"));
#endif
	return FALSE;
    }

    // set and check core dump generation
    rl = (struct rlimit *) grg_malloc(sizeof(struct rlimit));
    rl->rlim_cur = rl->rlim_max = 0;
    setrlimit(RLIMIT_CORE, rl);
    getrlimit(RLIMIT_CORE, rl);
    if (rl->rlim_cur || rl->rlim_max)	// no need to give any message, it 
					// should be impossible
	return FALSE;
    g_free(rl);

    // checks that stderr, stdin & stdout are opened
    canary = open("/dev/null", O_RDONLY);
    if (canary < 3) {
	g_critical("%s",
		   _
		   ("stdin, stdout and/or stderr are invalid. Cannot continue."));
	close(canary);
	return FALSE;
    }
    close(canary);

    // extract needed environmental vars, validate, erase environment,
    // and re-set them (see Secure Programming HowTo, sect.4.2)

    // extract
    lang = getenv("LANG");
    htab = getenv("HTAB");
#ifdef ENV_CHECK
    // validate
    if (lang) {
        grg_compile_re(&regexp, "^[[:alpha:]][-[:alnum:]_,+@.=]*$",
                       REG_EXTENDED|REG_NOSUB);
        if (regexec(&regexp, lang, 0, NULL, 0)) {
            g_critical("%s `%s'",
                       _("Invalid LANG environment variable:"), lang);
            return FALSE;
        }
    }
    xauth = getenv("XAUTHORITY");
    if (xauth && !g_file_test(xauth, G_FILE_TEST_EXISTS)) {
        g_critical("%s `%s'",
                   _("Invalid XAUTHORITY environment variable:"), xauth);
        return FALSE;
    }
    display = getenv("DISPLAY");
    if (display) {
        grg_compile_re(&regexp,
                       ":[[:digit:]]+(\\.[[:digit:]]+)?$",
                       REG_EXTENDED|REG_NOSUB);
        if (regexec(&regexp, display, 0, NULL, 0)) {
            g_critical("%s `%s'", _("Invalid DISPLAY environment variable:"),
                       display);
            return FALSE;
        }
    }
#endif

    // don't know why, but it seems necessary
    setlocale(LC_ALL, lang);
    mapIsUTF = g_get_charset(NULL);

#ifdef ENV_CHECK
    // erase
#ifdef HAVE_CLEARENV
    clearenv();
#else
#ifdef HAVE_ENVIRON
    {
	extern char   **environ;

	environ = NULL;
    }
#endif
#endif

    // re-set (warning: don't free() the g_strconcat'ed strings)
    if (lang != NULL)
	putenv(g_strconcat("LANG=", lang, NULL));
    if (display != NULL)
        putenv(g_strconcat("DISPLAY=", display, NULL));
    if (htab != NULL)
	putenv(g_strconcat("HTAB=", htab, NULL));
    putenv(g_strconcat("DISPLAY=", display, NULL));
    if (xauth != NULL)
	putenv(g_strconcat("XAUTHORITY=", xauth, NULL));
    putenv(g_strconcat("HOME=", g_get_home_dir(), NULL));
#endif

    // necessary to handle files correctly
    if (!mapIsUTF)
	putenv("G_BROKEN_FILENAMES=1");

    // this enables a stronger check on malloc() routines
#ifdef MAINTAINER_MODE
    putenv("MALLOC_CHECK_=2");
#else
    putenv("MALLOC_CHECK_=0");
#endif

    // initializes the security level indicator
    if (!(geteuid() && getegid() && getuid() && getgid()))
	change_sec_level(GRG_UNSAFE);

#ifdef HAVE_MLOCKALL
    if (!mem_safe)
	change_sec_level(GRG_UNSAFE);
#endif

    if (!ptrace_safe)
	change_sec_level(GRG_UNSAFE);

#ifndef ENV_CHECK
    change_sec_level(GRG_UNSAFE);
#endif

    if (grg_ctx_get_security_lvl(gctx) != GRG_SEC_PARANOIA)
	change_sec_level(GRG_SLIGHTLY_UNSAFE);

#ifndef ROOT_FILTER
    if (safety_level == GRG_SAFE)
	change_sec_level(GRG_SLIGHTLY_UNSAFE);
#endif

    return TRUE;
}

GtkWidget      *
grg_get_security_button(void)
{
    GdkPixbuf      *pix;
    GtkWidget      *img;

    switch (safety_level) {
    case GRG_SAFE:
	pix = gdk_pixbuf_new_from_xpm_data(optimal_xpm);
	break;
    case GRG_SLIGHTLY_UNSAFE:
	pix = gdk_pixbuf_new_from_xpm_data(green_xpm);
	break;
    case GRG_UNSAFE:
    default:
	pix = gdk_pixbuf_new_from_xpm_data(red_xpm);
	break;
    }

    img = gtk_image_new_from_pixbuf(pix);
    gtk_misc_set_alignment(GTK_MISC(img), 0.5f, 0.0f);
    g_object_unref(G_OBJECT(pix));

    return img;
}

gchar          *
grg_get_security_text(gchar * pattern)
{
    switch (safety_level) {
    case GRG_SAFE:
	return g_strdup_printf(pattern, _("optimal"));
    case GRG_SLIGHTLY_UNSAFE:
	return g_strdup_printf(pattern, _("good"));
    case GRG_UNSAFE:
    default:
	return g_strdup_printf(pattern, _("low"));
    }
}

#define ADD_INDICATOR(box, text, pixbuf) \
	{ \
		GtkWidget *new_lbl, *img, *hbox; \
		new_lbl = gtk_label_new(text); \
		gtk_misc_set_alignment(GTK_MISC(new_lbl), 0, 0.5); \
		img = gtk_image_new_from_pixbuf (pixbuf); \
		hbox = gtk_hbox_new (FALSE, GRG_PAD); \
		gtk_box_pack_start(GTK_BOX(hbox), img, FALSE, FALSE, GRG_PAD); \
		gtk_box_pack_start(GTK_BOX(hbox), new_lbl, FALSE, FALSE, GRG_PAD); \
		gtk_box_pack_start(GTK_BOX(box), hbox, FALSE, FALSE, GRG_PAD); \
	}

void
grg_security_monitor(void)
{
    GtkWidget      *dialog =
	gtk_dialog_new_with_buttons(_("Security monitor"),
				    NULL,
				    GTK_DIALOG_MODAL |
				    GTK_DIALOG_DESTROY_WITH_PARENT,
				    GTK_STOCK_OK,
				    GTK_RESPONSE_OK,
				    NULL);
    GdkPixbuf      *red = gdk_pixbuf_new_from_xpm_data(red_xpm);
    GdkPixbuf      *yellow = gdk_pixbuf_new_from_xpm_data(yellow_xpm);
    GdkPixbuf      *green = gdk_pixbuf_new_from_xpm_data(green_xpm);
    struct rlimit  *rl =
	(struct rlimit *) grg_malloc(sizeof(struct rlimit));

    if (!geteuid() || !getegid()) {
	ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
		      _("Running without root privileges"), red);
    } else {
	if (!getuid() || !getgid()) {
	    ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
			  _("Running without root privileges"), yellow);
	} else {
	    ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
			  _("Running without root privileges"), green);
	}
    }
    getrlimit(RLIMIT_CORE, rl);
    if (rl->rlim_cur || rl->rlim_max) {
	ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
		      _("Memory protection from core dumps"), red);
    } else {
	ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
		      _("Memory protection from core dumps"), green);
    }
    g_free(rl);

#ifdef HAVE_MLOCKALL
    // the pwd isn't stored in cleartext anyway
    if (mem_safe) {
	ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
		      _("Memory protection from swap writings"), green);
    } else {
	ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
		      _("Memory protection from swap writings"), yellow);
    }
#endif
    if (ptrace_safe) {
	ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
		      _("Memory protection from ptrace spying"), green);
    } else {
	ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
		      _("Memory protection from ptrace spying"), red);
    }
#if defined(ENV_CHECK) && (defined(HAVE_CLEARENV) || defined(HAVE_ENVIRON))
    ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
		  _("Environmental variables validation"), green)
#else
    ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
		  _("Environmental variables validation"), red)
#endif
	ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
		      _("stdout/stdin/stderr validation"), green)
	if (grg_ctx_get_security_lvl(gctx) == GRG_SEC_PARANOIA) {
	ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
		      _("Enforced use of /dev/random"), green);
    } else {
	ADD_INDICATOR(GTK_DIALOG(dialog)->vbox,
		      _("Enforced use of /dev/random"), yellow);
    }
#ifdef ROOT_FILTER
    ADD_INDICATOR(GTK_DIALOG(dialog)->
		  vbox, _("Strict prohibition to root user"), green)
#else
    ADD_INDICATOR(GTK_DIALOG(dialog)->
		  vbox, _("Strict prohibition to root user"), yellow)
#endif
	gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    g_object_unref(G_OBJECT(red));
    g_object_unref(G_OBJECT(yellow));
    g_object_unref(G_OBJECT(green));
    gtk_widget_destroy(dialog);
}

/*
 * Opens a file, only if it is regular and existent
 */
gint
grg_safe_open(gchar * path)
{
    struct stat buf1, buf2;
    gint res1, res2, fd;

    res1 = lstat(path, &buf1);

    if (res1)
	return GRG_OPEN_FILE_NOT_FOUND;

    if (!S_ISREG(buf1.st_mode))
	return GRG_OPEN_FILE_IRREGULAR;

    fd = open(path, O_RDONLY);

    if (fd < 3) {
	close(fd);
	return GRG_OPEN_FILE_NOT_FOUND;
    }

    res2 = fstat(fd, &buf2);

    if ((res1 != res2) ||
	(buf1.st_dev != buf2.st_dev) || (buf1.st_ino != buf2.st_ino) ||
	(buf1.st_uid != buf2.st_uid) || (buf1.st_gid != buf2.st_gid) ||
	(buf1.st_size != buf2.st_size)
	|| (buf1.st_blksize != buf2.st_blksize)
	|| (buf1.st_mtime != buf2.st_mtime)
	|| (buf1.st_ctime != buf2.st_ctime)
	|| (buf1.st_mode != buf2.st_mode)) {
	close(fd);
	return GRG_OPEN_SECURITY_FAULT;
    }

    return fd;
}

/*
 * Check that all mallocs return no errors
 */
gpointer
grg_malloc(gulong length)
{
    gpointer        ret = g_try_malloc(length);

#ifdef MAINTAINER_MODE
    // warn if a malloc(0) is attempted
    if (!length)
	g_warning("zero-length malloc() requested!");
#endif

    if (ret)
	return ret;

    printf("error: malloc failed. Probably this indicates a memory "
	   "problem, such as resource exhaustion. Attempting "
	   "to exit cleanly...");
    emergency_quit();

    // never really reached ;-)
    return NULL;
}

/*
 * Check that all reallocs return no errors
 */
gpointer
grg_realloc(gpointer ptr, gulong length)
{
    gpointer        ret = g_try_realloc(ptr, length);

#ifdef MAINTAINER_MODE
    // warn if a realloc(0) is attempted
    if (!length)
	g_warning("zero-length realloc() requested!");
#endif

    if (ret)
	return ret;

    printf("error: malloc failed. Probably this indicates a memory "
	   "problem, such as resource exhaustion. Attempting "
	   "to exit cleanly...");
    emergency_quit();

    return ret;
}
