INCLUDES = \
	@DEFS@ @GTK2_CFLAGS@ @GDKPIX_CFLAGS@ @LIBGRG_CFLAGS@	\
	-DG_LOG_DOMAIN=\"gringotts\" 			\
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-DDOCDIR=\"$(docdir)\" \
	-DG_DISABLE_DEPRECATED 					\
	-DGDK_PIXBUF_DISABLE_DEPRECATED 		\
	-DGDK_DISABLE_DEPRECATED 				\
	-Wpointer-arith  \
	-Werror-implicit-function-declaration -Wstrict-prototypes -Wall

# Remming out from INCLUDES so it won't disturb us with gtk+-2.13.x
#	-DGTK_DISABLE_DEPRECATED

bin_PROGRAMS = gringotts

gringotts_SOURCES = 						\
	gringotts.c 		gringotts.h			\
	grg_widgets.c 		grg_widgets.h		\
	grg_entries.c 		grg_entries.h		\
	grg_entries_vis.c	grg_entries_vis.h	\
	grg_list.c 			grg_list.h			\
	grg_menus.c 		grg_menus.h			\
	grg_prefs.c 		grg_prefs.h			\
	grg_prefs_io.c 		grg_prefs_io.h		\
	grg_pwd.c 			grg_pwd.h			\
	grg_safe.c 			grg_safe.h			\
	grg_recent_dox.c	grg_recent_dox.h	\
	grg_popt.c			grg_popt.h			\
	grg_pix.c			grg_pix.h			\
	grg_attachs.c		grg_attachs.h		\
	grg_defs.h

gringotts_LDADD = @POPT@ @GTK2_LIBS@ @GDKPIX_LIBS@ @LIBGRG_LIBS@

install-exec-local:
	strip $(DESTDIR)$(bindir)/gringotts
	chmod u+s $(DESTDIR)$(bindir)/gringotts
	
