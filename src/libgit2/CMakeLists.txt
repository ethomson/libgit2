include(PkgBuildConfig)

list(APPEND LIBGIT2_INCLUDES
	"${libgit2_BINARY_DIR}/src/generated"
	"${libgit2_SOURCE_DIR}/src/util"
	"${libgit2_SOURCE_DIR}/src/libgit2"
	"${libgit2_SOURCE_DIR}/include")

file(GLOB SRC_H
	"${libgit2_SOURCE_DIR}/include/git2.h"
	"${libgit2_SOURCE_DIR}/include/git2/*.h"
	"${libgit2_SOURCE_DIR}/include/git2/sys/*.h")

# On Windows use specific platform sources
if(WIN32 AND NOT CYGWIN)
	if(MSVC)
		set(WIN_RC "win32/git2.rc")
	endif()

	list(APPEND LIBGIT2_INCLUDES "${libgit2_SOURCE_DIR}/src/util/win32")
	file(GLOB SRC_OS win32/*.c win32/*.h)
elseif(AMIGA)
	add_definitions(-DNO_ADDRINFO -DNO_READDIR_R -DNO_MMAP)
else()
	file(GLOB SRC_OS unix/*.c unix/*.h)
endif()

file(GLOB SRC_GIT2 *.c *.h
	streams/*.c streams/*.h
	transports/*.c transports/*.h
	xdiff/*.c xdiff/*.h)

if(APPLE)
	# The old Secure Transport API has been deprecated in macOS 10.15.
	set_source_files_properties(streams/stransport.c PROPERTIES COMPILE_FLAGS -Wno-deprecated)
endif()

# the xdiff dependency is not (yet) warning-free, disable warnings as
# errors for the xdiff sources until we've sorted them out
if(MSVC)
	set_source_files_properties(xdiff/xdiffi.c PROPERTIES COMPILE_FLAGS -WX-)
	set_source_files_properties(xdiff/xutils.c PROPERTIES COMPILE_FLAGS -WX-)
endif()

set(LIBGIT2_SOURCES ${SRC_H} ${SRC_GIT2} ${SRC_OS} ${SRC_SSH})

add_library(libgit2 OBJECT ${LIBGIT2_SOURCES})
set_target_properties(libgit2 PROPERTIES C_STANDARD 90)
ide_split_sources(libgit2)
list(APPEND LIBGIT2_OBJECTS $<TARGET_OBJECTS:libgit2>)
list(APPEND LIBGIT2_OBJECTS $<TARGET_OBJECTS:util>)

target_include_directories(libgit2 PRIVATE ${LIBGIT2_INCLUDES} PUBLIC ${libgit2_SOURCE_DIR}/include)
target_include_directories(libgit2 SYSTEM PRIVATE ${LIBGIT2_SYSTEM_INCLUDES})

if(XCODE_VERSION)
	# This is required for Xcode to actually link the libgit2 library
	# when using only object libraries.
	file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dummy.c "")
	list(APPEND LIBGIT2_OBJECTS ${CMAKE_CURRENT_BINARY_DIR}/dummy.c)
endif()

# Compile and link libgit2
add_library(libgit2_meta ${WIN_RC} ${LIBGIT2_OBJECTS})
target_link_libraries(libgit2_meta ${LIBGIT2_LIBS})

set_target_properties(libgit2_meta PROPERTIES C_STANDARD 90)
set_target_properties(libgit2_meta PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${libgit2_BINARY_DIR})
set_target_properties(libgit2_meta PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${libgit2_BINARY_DIR})
set_target_properties(libgit2_meta PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${libgit2_BINARY_DIR})

# Workaround for Cmake bug #0011240 (see http://public.kitware.com/Bug/view.php?id=11240)
# Win64+MSVC+static libs = linker error
if(MSVC AND GIT_ARCH_64 AND NOT BUILD_SHARED_LIBS)
	set_target_properties(libgit2_meta PROPERTIES STATIC_LIBRARY_FLAGS "/MACHINE:x64")
endif()

ide_split_sources(libgit2_meta)

if(SONAME)
	set_target_properties(libgit2_meta PROPERTIES VERSION ${LIBGIT2_VERSION_STRING})
	set_target_properties(libgit2_meta PROPERTIES SOVERSION ${LIBGIT2_SOVERSION})
	if(LIBGIT2_FILENAME)
		add_definitions(-DLIBGIT2_FILENAME=\"${LIBGIT2_FILENAME}\")
		set_target_properties(libgit2_meta PROPERTIES OUTPUT_NAME ${LIBGIT2_FILENAME})
	elseif(DEFINED LIBGIT2_PREFIX)
		set_target_properties(libgit2_meta PROPERTIES PREFIX "${LIBGIT2_PREFIX}")
	else()
		set_target_properties(libgit2_meta PROPERTIES OUTPUT_NAME git2)
	endif()
endif()

pkg_build_config(NAME libgit2
	VERSION ${LIBGIT2_VERSION_STRING}
	DESCRIPTION "A cross-platform, linkable library implementation of Git that you can use in your application."
	LIBS_SELF libgit2_meta
	PRIVATE_LIBS ${LIBGIT2_PC_LIBS}
	REQUIRES ${LIBGIT2_PC_REQUIRES}
)

if(MSVC_IDE)
   # Precompiled headers
	set_target_properties(libgit2_meta PROPERTIES COMPILE_FLAGS "/Yuprecompiled.h /FIprecompiled.h")
	set_source_files_properties(win32/precompiled.c COMPILE_FLAGS "/Ycprecompiled.h")
endif()

# Install
install(TARGETS libgit2_meta
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY ${libgit2_SOURCE_DIR}/include/git2 DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${libgit2_SOURCE_DIR}/include/git2.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# export these variables for the test framework; it links our object
# files directly (instead of linking to libgit2.so) so that it can
# test private and internal functions.
set_property(GLOBAL PROPERTY libgit2_objects ${LIBGIT2_OBJECTS})
set_property(GLOBAL PROPERTY libgit2_includes ${LIBGIT2_INCLUDES})
set_property(GLOBAL PROPERTY libgit2_system_includes ${LIBGIT2_SYSTEM_INCLUDES})
set_property(GLOBAL PROPERTY libgit2_libs ${LIBGIT2_LIBS})
