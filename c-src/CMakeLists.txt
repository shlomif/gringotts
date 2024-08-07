# This CMakeLists.txt file is based on the one from sakura:
#
# http://www.pleyades.net/david/sakura.php

CMAKE_MINIMUM_REQUIRED (VERSION 3.8 FATAL_ERROR)

INCLUDE ("${CMAKE_SOURCE_DIR}/cmake/shlomif_common_bootstrap.cmake")
SHLOMIF_COMMON_SETUP("${private_mod_path}")

# Introduces VERSION , CPACK_PACKAGE_VERSION_MAJOR,
# CPACK_PACKAGE_VERSION_MAJOR, and CPACK_PACKAGE_VERSION_PATCH
READ_VERSION_FROM_VER_TXT()

# This is the equivalent to perform a "make dist"/"make distdir" etc.
SET(CPACK_PACKAGE_NAME "gringotts")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Gringotts - a safebox for your data")
SET(CPACK_PACKAGE_VENDOR "Shlomi Fish")
SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")


SET(CPACK_PACKAGE_INSTALL_DIRECTORY "${CPACK_PACKAGE_DESCRIPTION_SUMMARY} ${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

SET (base_with_ver "${CPACK_PACKAGE_NAME}-[0-9]+\\\\.[0-9]+\\\\.[0-9]+")

SET(CPACK_SOURCE_IGNORE_FILES
    "/_CPack_Packages/"
    "/CMakeFiles/"
    "/.deps/"
    "\\\\.tidyall\\\\.d"
    "^${base_with_ver}(-Source|-Linux)?/"
    "${base_with_ver}.tar\\\\.(gz|bz2|Z|lzma|xz)$"
    "\\\\.o$"
    "~$"
    "/lib(fcs|freecell-solver)\\\\.(a|la)$"
    "\\\\.so(\\\\.[0-9]+)*$"
    "/\\\\.svn/"
    "\\\\.(pdf|fo)$"
    "/t/t/.*\\\\.exe$"
    "\\\\.pyc$"
    "/t/Presets"
    "/CMakeCache\\\\.txt$"
    "/Makefile$"
    "/CTestTestfile\\\\.cmake$"
    "/cmake_install\\\\.cmake$"
    "/CPackConfig\\\\.cmake$"
    "/CPackSourceConfig\\\\.cmake$"
    "/tags$"
    "/freecell-solver-config$"
    "/libfreecell-solver\\\\.pc$"
    "/([0-9]+)\\\\.board$"
    "/config\\\\.h$"
    "/install_manifest\\\\.txt$"
    "/t/card-test-(parse|render)\\\\.c$"
    "/Testing/"
    "ids-whitelist\\\\.txt"
    "/_Inline/"
    "/(build|BUILD|B)/"
    "/Presets/testing-presets"
)

INCLUDE ("${CMAKE_SOURCE_DIR}/cmake/rinutils_bootstrap.cmake")

RINUTILS_SET_UP_FLAGS()

IF(WIN32 AND NOT UNIX)
    # There is a bug in NSI that does not handle full unix paths properly. Make
    # sure there is at least one set of four (4) backlasshes.
    # SET(CPACK_PACKAGE_ICON "${CMAKE_SOURCE_DIR}\\\\dondorf-king.bmp")
    # SET(CPACK_NSIS_INSTALLED_ICON_NAME "bin\\\\fc-solve.exe")
    SET(CPACK_NSIS_HELP_LINK "http:\\\\\\\\gringotts.shlomifish.org")
    SET(CPACK_NSIS_URL_INFO_ABOUT "http:\\\\\\\\gringotts.shlomifish.org")
    SET(CPACK_NSIS_DISPLAY_NAME "Gringotts")
    SET(CPACK_NSIS_CONTACT "shlomif@shlomifish.org")
    SET(CPACK_NSIS_MODIFY_PATH ON)
    # Setting for NSIS :
    # SET(CPACK_NSIS_MUI_ICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\fc-solve.ico")
    # SET(CPACK_NSIS_MUI_UNIICON ${CPACK_NSIS_MUI_ICON})
    # SET(CPACK_PACKAGE_ICON ${CPACK_NSIS_MUI_ICON})
    SET(CPACK_NSIS_MODIFY_PATH "ON")
ELSE(WIN32 AND NOT UNIX)
  SET(CPACK_STRIP_FILES "gringotts")
  SET(CPACK_SOURCE_STRIP_FILES "")
ENDIF(WIN32 AND NOT UNIX)

SET(CPACK_PACKAGE_EXECUTABLES
    "gringotts" "Gringotts"
)

PROJECT (gringotts)
SET (AUTHOR "Shlomi Fish" INTERNAL "Author")
SET (VERSION "1.4.0")
SET (GRG_NAME "gringotts")
SET (GETTEXT_PACKAGE "\"${GRG_NAME}\"")
SET (GRG_CAP_NAME "\"Gringotts\"")
SET (GRG_VERSION "\"1.4.0\"")
SET (GRG_FILE_SUBVERSION "\"3\"")
SET (BLOCK_DEV "/dev/fd0" CACHE STRING "The block device to use for a password")
SET (BLOCK_DEV_IS_FLOPPY TRUE CACHE BOOL "Is the block device a floppy disk.")

INCLUDE (CPack)
INCLUDE (FindPkgConfig)

IF (NOT PKG_CONFIG_FOUND)
	MESSAGE (FATAL_ERROR "pkg-config not found...")
ENDIF (NOT PKG_CONFIG_FOUND)

pkg_check_modules (GTK REQUIRED gtk+-3.0>=3.0)
IF (NOT GTK_FOUND)
	MESSAGE(FATAL_ERROR "You don't seem to have gtk >= 2.10 development libraries installed...")
ENDIF (NOT GTK_FOUND)

pkg_check_modules (GDKPIX REQUIRED gdk-pixbuf-2.0)
IF (NOT GDKPIX_FOUND)
	MESSAGE(FATAL_ERROR "You don't seem to have gdk-pixbuf-2.0 development libraries installed...")
ENDIF (NOT GDKPIX_FOUND)

pkg_check_modules (LIBGRG REQUIRED libgringotts>=1.2)
IF (NOT LIBGRG_FOUND)
	MESSAGE(FATAL_ERROR "You don't seem to have libgringotts >= 1.2.0 development libraries installed...")
ENDIF (NOT LIBGRG_FOUND)

pkg_check_modules (POPT REQUIRED popt)
IF (NOT POPT_FOUND)
	MESSAGE(FATAL_ERROR "You don't seem to have popt development libraries installed...")
ENDIF (NOT POPT_FOUND)

# FIND_PROGRAM(POD2MAN pod2man)
# MESSAGE ("pod2man executable is" ${POD2MAN})

# ADD_DEFINITIONS (-DVERSION=\\\"${VERSION}\\\")
# ADD_DEFINITIONS (-DDATADIR=\\\"${CMAKE_INSTALL_PREFIX}/share\\\")
# ADD_DEFINITIONS (-DBUILDTYPE=\\\"${CMAKE_BUILD_TYPE}\\\")
ADD_DEFINITIONS (-DHAVE_CONFIG_H=1)
ADD_DEFINITIONS (-DLOCALEDIR=\"${CMAKE_INSTALL_PREFIX}/share/locale\")
ADD_DEFINITIONS (-DDOCDIR=\"${CMAKE_INSTALL_PREFIX}/share/doc\")
ADD_DEFINITIONS (
        "-Werror=implicit-function-declaration"
)
IF (${CMAKE_BUILD_TYPE} MATCHES "Debug")
	SET (CMAKE_C_FLAGS "-Wall")
ELSE (${CMAKE_BUILD_TYPE} NOT MATCHES "Debug")
	SET (CMAKE_C_FLAGS "-O2")
ENDIF (${CMAKE_BUILD_TYPE} MATCHES "Debug")

IF ("$ENV{FCS_CLANG}")
    # ADD_DEFINITIONS("-Weverything -Wno-language-extension-token -Wno-padded -Wno-gnu-statement-expression -Wno-unused-parameter -Wno-vla -Wno-cast-align -Wno-used-but-marked-unused -Wno-cast-qual -Wno-comma -Wno-disabled-macro-expansion -Wno-extra-semi-stmt -Wno-documentation-unknown-command -Wno-documentation -Wno-documentation-deprecated-sync -Wno-pass-failed -Wno-implicit-fallthrough")
    # ADD_DEFINITIONS("-Weverything")
    ADD_DEFINITIONS("-Weverything -Wno-deprecated-declarations -Wno-documentation-unknown-command -Wno-documentation -Wno-padded -Wno-reserved-id-macro")
ENDIF ()

IF ("$ENV{FCS_GCC}")
    ADD_DEFINITIONS("-W -Wabi=11 -Waddress -Waggressive-loop-optimizations -Wall -Wattributes -Wbad-function-cast -Wbool-compare -Wbool-operation -Wbuiltin-declaration-mismatch -Wbuiltin-macro-redefined -Wcast-align -Wchar-subscripts -Wclobbered -Wcomment -Wcomments -Wcoverage-mismatch -Wcpp -Wdangling-else -Wdate-time -Wdeprecated -Wdeprecated-declarations -Wdesignated-init -Wdisabled-optimization -Wdiscarded-array-qualifiers -Wdiscarded-qualifiers -Wdiv-by-zero -Wdouble-promotion -Wduplicated-branches -Wduplicated-cond -Wduplicate-decl-specifier -Wempty-body -Wendif-labels -Wenum-compare -Wexpansion-to-defined -Wextra -Wformat-contains-nul -Wformat-extra-args -Wformat-nonliteral -Wformat-security -Wformat-signedness -Wformat-y2k -Wformat-zero-length -Wframe-address -Wfree-nonheap-object -Whsa -Wignored-attributes -Wignored-qualifiers -Wimplicit -Wimplicit-function-declaration -Wimplicit-int -Wincompatible-pointer-types -Winit-self -Winline -Wint-conversion -Wint-in-bool-context -Wint-to-pointer-cast -Winvalid-memory-model -Winvalid-pch -Wjump-misses-init -Wlogical-not-parentheses -Wlogical-op -Wmain -Wmaybe-uninitialized -Wmemset-elt-size -Wmemset-transposed-args -Wmisleading-indentation -Wmissing-braces -Wmissing-declarations -Wmissing-field-initializers -Wmissing-include-dirs -Wmissing-parameter-type -Wmissing-prototypes -Wmultichar -Wnarrowing -Wnested-externs -Wnonnull -Wnonnull-compare -Wnull-dereference -Wodr -Wold-style-declaration -Wold-style-definition -Wopenmp-simd -Woverflow -Woverlength-strings -Woverride-init -Wpacked -Wpacked-bitfield-compat -Wparentheses -Wpointer-arith -Wpointer-compare -Wpointer-sign -Wpointer-to-int-cast -Wpragmas -Wpsabi -Wrestrict -Wreturn-local-addr -Wreturn-type -Wscalar-storage-order -Wsequence-point -Wshadow -Wshift-count-negative -Wshift-count-overflow -Wshift-negative-value -Wsizeof-array-argument -Wsizeof-pointer-memaccess -Wstack-protector -Wstrict-aliasing -Wstrict-prototypes  -Wsuggest-attribute=format -Wsuggest-attribute=noreturn -Wsuggest-attribute=pure -Wsuggest-final-methods -Wsuggest-final-types -Wswitch -Wswitch-bool -Wswitch-default -Wswitch-unreachable -Wsync-nand -Wtautological-compare -Wtrampolines -Wtrigraphs -Wtype-limits -Wuninitialized -Wunknown-pragmas -Wunsafe-loop-optimizations -Wunused -Wunused-but-set-parameter -Wunused-but-set-variable -Wunused-function -Wunused-label -Wunused-local-typedefs -Wunused-macros -Wunused-parameter -Wunused-result -Wunused-value -Wunused-variable -Wvarargs -Wvariadic-macros -Wvector-operation-performance -Wvla -Wvolatile-register-var -Wwrite-strings -Walloc-size-larger-than=9223372036854775807 -Warray-bounds=2 -Wformat-overflow=2 -Wformat-truncation=2 -Wnormalized=nfc -Wshift-overflow=2  -Wunused-const-variable=2 -Wstrict-overflow=1  -Wno-switch-default -Wno-vla -Wno-inline  -Wno-jump-misses-init -Wno-unsafe-loop-optimizations -Wno-unused-result")
    # -Wimplicit-fallthrough=5
    # -Wno-vla-larger-than
    # -Wsuggest-attribute=const
    # -Wstringop-overflow=2

    IF (NOT IS_DEBUG)
        ADD_DEFINITIONS("-D_FORTIFY_SOURCE=2")
    ELSE ()
        ADD_DEFINITIONS("-D_FORTIFY_SOURCE=2")
    ENDIF ()
        ADD_DEFINITIONS("-O1")
ENDIF ()

INCLUDE_DIRECTORIES (. ${GTK_INCLUDE_DIRS} ${GDKPIX_INCLUDE_DIRS} ${LIBGRG_INCLUDE_DIRS} ${POPT_INCLUDE_DIRS})
LINK_DIRECTORIES (${GTK_LIBRARY_DIRS} ${GDKPIX_LIBRARY_DIRS} ${LIBGRG_LIBRARY_DIRS} ${POPT_LIBRARY_DIRS} )
LINK_LIBRARIES (${GTK_LIBRARIES} ${GDKPIX_LIBRARIES} ${LIBGRG_LIBRARIES} ${POPT_LIBRARIES})

# So it can find the src includes.
INCLUDE_DIRECTORIES(BEFORE "${CMAKE_CURRENT_SOURCE_DIR}/src")

# So it can find config.h
INCLUDE_DIRECTORIES(BEFORE "${CMAKE_CURRENT_BINARY_DIR}")

ADD_EXECUTABLE (gringotts-exe
        src/gringotts.c
        src/grg_widgets.c
        src/grg_entries.c
        src/grg_entries_vis.c
        src/grg_list.c
        src/grg_menus.c
        src/grg_prefs.c
        src/grg_prefs_io.c
        src/grg_pwd.c
        src/grg_safe.c
        src/grg_recent_dox.c
        src/grg_popt.c
        src/grg_pix.c
        src/grg_attachs.c
        src/grg_xpm.c
        )

ADD_SUBDIRECTORY (po)

INSTALL (PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/gringotts-exe" DESTINATION bin RENAME "gringotts")
# INSTALL (FILES sakura.desktop DESTINATION share/applications)
# INSTALL (FILES terminal-tango.svg DESTINATION share/pixmaps)
#IF (POD2MAN)
#	INSTALL (FILES ${sakura_BINARY_DIR}/sakura.1 DESTINATION share/man/man1)
#ENDIF (POD2MAN)

# INSTALL (FILES INSTALL DESTINATION share/doc/sakura)

FILE (GLOB MO_FILES po/*.mo)

CONFIGURE_FILE(
    ${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/config.h
    )
