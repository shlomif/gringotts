# This CMakeLists.txt file is based on the one from sakura:
#
# http://www.pleyades.net/david/sakura.php

SET (private_mod_path "${CMAKE_SOURCE_DIR}/cmake")
LIST (APPEND CMAKE_MODULE_PATH "${private_mod_path}")
INCLUDE(Shlomif_Common)

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

CMAKE_MINIMUM_REQUIRED (VERSION 2.8 FATAL_ERROR)

IF (COMMAND CMAKE_POLICY)
	CMAKE_POLICY(SET CMP0005 OLD)
ENDIF (COMMAND CMAKE_POLICY)
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

pkg_check_modules (GTK REQUIRED gtk+-2.0>=2.12)
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
ADD_DEFINITIONS (-DLOCALEDIR=\\\"${CMAKE_INSTALL_PREFIX}/share/locale\\\")
ADD_DEFINITIONS (-DDOCDIR=\\\"${CMAKE_INSTALL_PREFIX}/share/doc\\\")

IF (${CMAKE_BUILD_TYPE} MATCHES "Debug")
	SET (CMAKE_C_FLAGS "-Wall")
ELSE (${CMAKE_BUILD_TYPE} NOT MATCHES "Debug")
	SET (CMAKE_C_FLAGS "-O2")
ENDIF (${CMAKE_BUILD_TYPE} MATCHES "Debug")

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

# ADD_DEPENDENCIES (sakura src/sakura.c src/sakura.h)

ADD_SUBDIRECTORY (po)

INSTALL (TARGETS "gringotts-exe" RUNTIME DESTINATION bin RENAME "gringotts")
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

SET_DIRECTORY_PROPERTIES (PROPERTIES
	ADDITIONAL_MAKE_CLEAN_FILES "${MO_FILES};po/sakura.pot")
SET (EXECUTABLE_OUTPUT_PATH src)

ADD_CUSTOM_TARGET (distclean
	rm -f Makefile cmake_install.cmake CMakeCache.txt install_manifest.txt
	COMMAND rm -f po/*.mo po/gringotts.pot po/Makefile po/cmake_install.cmake
	COMMAND rm -rf CMakeFiles po/CMakeFiles)

# IF (POD2MAN)
# ADD_CUSTOM_TARGET(man ALL
# 	COMMAND ${POD2MAN} -u --section=1 --release=${VERSION} --center '' ${gringotts_SOURCE_DIR}/gringotts.pod grin.1)
# ENDIF (POD2MAN)
