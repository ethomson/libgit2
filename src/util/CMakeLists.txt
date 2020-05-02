INCLUDE(SelectHashes)

SET(LIBGIT2_UTIL_INCLUDES
	"${libgit2_BINARY_DIR}/src/generated"
	"${libgit2_SOURCE_DIR}/src/util")

# Collect sourcefiles
FILE(GLOB SRC_UTIL_H
	"${libgit2_SOURCE_DIR}/include/git2.h"
	"${libgit2_SOURCE_DIR}/include/git2/*.h"
	"${libgit2_SOURCE_DIR}/include/git2/sys/*.h")

FILE(GLOB SRC_UTIL *.c *.h ${SRC_SHA1} allocators/*.c allocators/*.h)

IF (WIN32 AND NOT CYGWIN)
ELSE()
	FILE(GLOB SRC_UTIL_OS
		unix/map.c unix/posix.h unix/pthread.h unix/realpath.c)
ENDIF()

# Utility functions shared with other parts of the libgit2
SET(UTIL_SOURCES ${SRC_UTIL} ${SRC_UTIL_OS})
ADD_LIBRARY(util OBJECT ${UTIL_SOURCES})
LIST(APPEND UTIL_OBJECTS $<TARGET_OBJECTS:util>)

TARGET_INCLUDE_DIRECTORIES(util PRIVATE ${LIBGIT2_UTIL_INCLUDES} PUBLIC ${libgit2_SOURCE_DIR}/include)
TARGET_INCLUDE_DIRECTORIES(util SYSTEM PRIVATE ${LIBGIT2_UTIL_SYSTEM_INCLUDES})

