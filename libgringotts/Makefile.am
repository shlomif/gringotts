SUBDIRS = src docs

libgringottsdocdir = $(datadir)/doc/libgringotts-@VERSION@
libgringottsdoc_DATA = TODO NEWS AUTHORS README COPYING ChangeLog

EXTRA_DIST = libgringotts.spec.in libgringotts.pc.in $(libgringottsdoc_DATA)

dist-hook: libgringotts.spec
	cp libgringotts.spec $(distdir)

install-exec-local:
	mkdir -p $(DESTDIR)$(pcdir)/
	cp libgringotts.pc $(DESTDIR)$(pcdir)/
	@echo
	@echo
	@echo ----------------------------------------------------------------------
	@echo   md5sum of relevant files:
	@echo
	@md5sum $(DESTDIR)$(libdir)/libgringotts.so|(read A B; echo $$B ":"; echo $$A)
	@echo
	@md5sum $(DESTDIR)$(includedir)/libgringotts.h|(read A B; echo $$B ":"; echo $$A)
	@echo
	@echo use these values to check library integrity at any time
	@echo ----------------------------------------------------------------------
	@echo
	@echo
	
uninstall-local:
	rm -f $(DESTDIR)$(libdir)/pkgconfig/libgringotts.pc
