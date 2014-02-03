INCLUDES = @DEFS@ @MCRYPT_CFLAGS@ -Wall -Wpointer-arith

lib_LTLIBRARIES = libgringotts.la

noinst_HEADERS = libgrg_crypt.h libgrg_structs.h libgrg_utils.h

include_HEADERS = libgringotts.h

libgringotts_la_SOURCES = libgrg_crypt.c libgrg_structs.c libgrg_utils.c libgrg_tmp.c 

libgringotts_la_LDFLAGS = -version-info @LIBGRG_INTERFACE@:@LIBGRG_RELEASE@:@LIBGRG_AGE@

libgringotts_la_LIBADD = @LIBZ@ @LIBBZ2@ @MCRYPT_LIBS@ @MHASH@ -lm

EXTRA_DIST = test.c

check-local: libgringotts.la
	@gcc test.c .libs/libgringotts.a -g @DEFS@ @MCRYPT_CFLAGS@ -Wall \
		-Wpointer-arith @LIBZ@ @LIBBZ2@ @MCRYPT_LIBS@ @MHASH@ -lm -o libgrgtest
	@./libgrgtest
	@rm -f libgrgtest test.o
