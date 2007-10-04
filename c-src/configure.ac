AC_INIT(gringotts, 1.2.9pre1, mano78@users.sourceforge.net)

GRG_NAME=$PACKAGE_NAME
GRG_CAP_NAME=Gringotts
GRG_VERSION=$PACKAGE_VERSION
GRG_FILE_SUBVERSION="3"

AM_INIT_AUTOMAKE($GRG_NAME, $GRG_VERSION)

AC_CONFIG_SRCDIR(src/gringotts.c)
AM_CONFIG_HEADER(config.h)

GETTEXT_PACKAGE=$GRG_NAME
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE", Package for GettText)

AC_SUBST(GRG_VERSION)
AC_SUBST(GRG_NAME)
AC_SUBST(GRG_CAP_NAME)
AC_SUBST(GRG_FILE_SUBVERSION)
AC_DEFINE_UNQUOTED(GRG_NAME, "$GRG_NAME", The program name)
AC_DEFINE_UNQUOTED(GRG_CAP_NAME, "$GRG_CAP_NAME", The program name with capital initial letter)
AC_DEFINE_UNQUOTED(GRG_VERSION, "$GRG_VERSION", The program version)
AC_DEFINE_UNQUOTED(GRG_FILE_SUBVERSION, "$GRG_FILE_SUBVERSION", The version of the XML format used to save files)

dnl Specify a configuration file

dnl additional ./configure options

AH_TEMPLATE(ENV_CHECK,[Validate the environmental variables at startup])

AC_ARG_ENABLE(env-check,
AC_HELP_STRING([--enable-env-check],[validate the environmental variables at startup (default=yes)]),
enable_env_check="$enableval", enable_env_check=yes)

if test "$enable_env_check" = yes; then
	AC_MSG_NOTICE(env validation active)
    AC_DEFINE(ENV_CHECK)
else
	AC_MSG_NOTICE(env validation inactive)
fi

AH_TEMPLATE(ROOT_FILTER,[Strictly forbids access to the root user])

AC_ARG_ENABLE(root-filter,
AC_HELP_STRING([--enable-root-filter],[strictly forbids access to the root user (default=no)]),
enable_root_filter="$enableval", enable_root_filter=no)

if test "$enable_root_filter" = yes; then
	AC_MSG_NOTICE(strict root check active)
    AC_DEFINE(ROOT_FILTER)
else
	AC_MSG_NOTICE(strict root check inactive)
fi

AH_TEMPLATE(MAINTAINER_MODE,[Enable checks normally unneeded])

AC_ARG_ENABLE(maintainer-mode,
AC_HELP_STRING([--enable-maintainer-mode],[enable some checks that are normally unneeded (default=no)]),
enable_maintainer_mode="$enableval", enable_maintainer_mode=no)

if test "$enable_maintainer_mode" = yes; then
	AC_MSG_NOTICE(maintainer checks active)
    AC_DEFINE(MAINTAINER_MODE)
else
	AC_MSG_NOTICE(maintainer checks inactive)
fi

AH_TEMPLATE(ATTACH_LIMIT,[Enable 2Mb limit to attachments])

AC_ARG_ENABLE(attach-limit,
AC_HELP_STRING([--enable-attach-limit],[enable 2Mb limit for attached files (default=yes)]),
enable_attach_limit="$enableval", enable_attach_limit=no)

if test "$enable_attach_limit" = yes; then
	AC_MSG_NOTICE(2Mb attachment limit active)
    AC_DEFINE(ATTACH_LIMIT)
else
	AC_MSG_NOTICE(2Mb attachment limit inactive)
fi

AH_TEMPLATE(BLOCK_DEV,[block device file to be used as password])

AC_ARG_WITH(floppy-device,
AC_HELP_STRING([--with-block-device=DEV],[specify the block device to be used as password (default=/dev/fd0)]),
with_floppy_device="$withval", with_floppy_device="/dev/fd0")

if test -b "$with_floppy_device"; then
	AC_MSG_NOTICE([valid block device found in $with_floppy_device])
    AC_DEFINE_UNQUOTED(BLOCK_DEV, "$with_floppy_device")
else
	AC_MSG_NOTICE([invalid block device $with_floppy_device, using /dev/fd0])
	AC_DEFINE(BLOCK_DEV, "/dev/fd0")
fi

AH_TEMPLATE(BLOCK_DEV_IS_FLOPPY,[BLOCK_DEV is a proper floppy device])
if test "`expr substr "$with_floppy_device" 1 7`" = "/dev/fd"; then
	AC_MSG_NOTICE([block device seems to be a floppy])
	AC_DEFINE(BLOCK_DEV_IS_FLOPPY)
fi

dnl Checks for programs.
AC_PROG_CC

ALL_LINGUAS="it fr de pl ru"
AM_GLIB_GNU_GETTEXT

dnl Checks for libraries.

AC_PATH_XTRA

PKG_CHECK_MODULES(GTK2, gtk+-2.0)
AC_SUBST(GTK2_CFLAGS)
AC_SUBST(GTK2_LIBS)

PKG_CHECK_MODULES(GDKPIX, gdk-pixbuf-2.0)
AC_SUBST(GDKPIX_CFLAGS)
AC_SUBST(GDKPIX_LIBS)

PKG_CHECK_MODULES(LIBGRG, libgringotts >= 1.2.0)
AC_SUBST(LIBGRG_CFLAGS)
AC_SUBST(LIBGRG_LIBS)

AC_CHECK_LIB(popt, poptGetContext,
  [AC_CHECK_HEADER(popt.h, POPT='-lpopt',
	[AC_MSG_ERROR(*** ERROR: POPT header files not found ***)])],
      [AC_MSG_ERROR(*** ERROR: POPT library not found ***)])
AC_SUBST(POPT)

AC_CHECK_FUNCS(mlockall tcgetattr clearenv environ isatty ttyname)

dnl Checks for header files.
AC_HEADER_STAT
AC_HEADER_STDC
AC_CHECK_HEADERS(sys/fsuid.h)
AC_CHECK_HEADERS(linux/fd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

dnl Checks for library functions.

AC_CONFIG_FILES(Makefile)
AC_CONFIG_FILES(src/Makefile)
AC_CONFIG_FILES(pixmaps/Makefile )
AC_CONFIG_FILES(po/Makefile.in)
AC_CONFIG_FILES(gringotts.spec)
AC_CONFIG_FILES(gringotts.desktop)
AC_OUTPUT
