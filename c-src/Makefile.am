SUBDIRS = src pixmaps po

doc_DATA = BUGS FAQ README AUTHORS ChangeLog TODO NEWS COPYING

EXTRA_DIST = gringotts.spec.in gringotts.desktop.in $(doc_DATA)
EXTRA_DIST += autogen.sh

Dsktpdir = $(datadir)/gnome/apps/Utilities
Dsktp_in_files = gringotts.desktop.in
Dsktp_DATA = $(Dsktp_in_files:.desktop.in=.desktop)

dist-hook: gringotts.spec
	cp gringotts.spec $(distdir)

install-exec-local:
	@echo
	@echo
	@echo ----------------------------------------------------------------------
	@echo   md5sum of relevant files:
	@echo
	@md5sum $(DESTDIR)$(bindir)/gringotts|(read A B; echo $$B ": " $$A)
	@echo
	@echo use this value to check program integrity at any time
	@echo ----------------------------------------------------------------------
	@echo
	@echo
