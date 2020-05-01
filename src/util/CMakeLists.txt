SET(LIBGIT2_UTIL_INCLUDES
	"${CMAKE_CURRENT_BINARY_DIR}"
	"${libgit2_SOURCE_DIR}/src/util")

IF(DEBUG_POOL)
	SET(GIT_DEBUG_POOL 1)
ENDIF()
ADD_FEATURE_INFO(debugpool GIT_DEBUG_POOL "debug pool allocator")

CHECK_FUNCTION_EXISTS(futimens HAVE_FUTIMENS)
IF (HAVE_FUTIMENS)
	SET(GIT_USE_FUTIMENS 1)
ENDIF ()

CHECK_PROTOTYPE_DEFINITION(qsort_r
	"void qsort_r(void *base, size_t nmemb, size_t size, void *thunk, int (*compar)(void *, const void *, const void *))"
	"" "stdlib.h" HAVE_QSORT_R_BSD)
IF (HAVE_QSORT_R_BSD)
	ADD_DEFINITIONS(-DHAVE_QSORT_R_BSD)
ENDIF()

CHECK_PROTOTYPE_DEFINITION(qsort_r
	"void qsort_r(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *, void *), void *arg)"
	"" "stdlib.h" HAVE_QSORT_R_GNU)
IF (HAVE_QSORT_R_GNU)
	ADD_DEFINITIONS(-DHAVE_QSORT_R_GNU)
ENDIF()

CHECK_FUNCTION_EXISTS(qsort_s HAVE_QSORT_S)
IF (HAVE_QSORT_S)
	ADD_DEFINITIONS(-DHAVE_QSORT_S)
ENDIF ()

CHECK_LIBRARY_EXISTS(rt clock_gettime "time.h" NEED_LIBRT)
IF(NEED_LIBRT)
	LIST(APPEND LIBGIT2_UTIL_LIBS rt)
	LIST(APPEND LIBGIT2_UTIL_PC_LIBS "-lrt")
ENDIF()

Include(SelectHashes)

# Optional external dependency: iconv
IF (USE_ICONV)
	FIND_PACKAGE(Iconv)
ENDIF()
IF (ICONV_FOUND)
	SET(GIT_USE_ICONV 1)
	LIST(APPEND LIBGIT2_UTIL_SYSTEM_INCLUDES ${ICONV_INCLUDE_DIR})
	LIST(APPEND LIBGIT2_UTIL_LIBS ${ICONV_LIBRARIES})
	LIST(APPEND LIBGIT2_UTIL_PC_LIBS ${ICONV_LIBRARIES})
ENDIF()
ADD_FEATURE_INFO(iconv GIT_USE_ICONV "iconv encoding conversion support")

IF (THREADSAFE)
	IF (NOT WIN32)
		FIND_PACKAGE(Threads REQUIRED)
	ENDIF()

	SET(GIT_THREADS 1)
ENDIF()

IF (USE_NSEC)
	SET(GIT_USE_NSEC 1)
ENDIF()

# Collect sourcefiles
FILE(GLOB SRC_H
	"${libgit2_SOURCE_DIR}/include/git2.h"
	"${libgit2_SOURCE_DIR}/include/git2/*.h"
	"${libgit2_SOURCE_DIR}/include/git2/sys/*.h")

# On Windows use specific platform sources
IF (WIN32 AND NOT CYGWIN)
	IF(MSVC)
		SET(WIN_RC "win32/git2.rc")
	ENDIF()

	FILE(GLOB SRC_OS win32/*.c win32/*.h)
ELSE()
	FILE(GLOB SRC_OS unix/*.c unix/*.h)
ENDIF()

FILE(GLOB SRC_UTIL alloc.c alloc.h buffer.c buffer.h buf_text.c buf_text.h
	futils.c futils.h hash.c hash.h ${SRC_SHA1} path.c path.h
	pool.c pool.h posix.c posix.h strarray.c strarray.h
	strmap.c strmap.h tsort.c util.c util.h vector.c vector.h
	allocators/*.c allocators/*.h)

IF (WIN32 AND NOT CYGWIN)
ELSE()
	FILE(GLOB SRC_UTIL_OS
		unix/map.c unix/posix.h unix/pthread.h unix/realpath.c)
ENDIF()

# Utility functions shared with other parts of the libgit2
SET(UTIL_SOURCES ${SRC_UTIL} ${SRC_UTIL_OS})
ADD_LIBRARY(git2util OBJECT ${UTIL_SOURCES})
LIST(APPEND UTIL_OBJECTS $<TARGET_OBJECTS:git2util>)

TARGET_INCLUDE_DIRECTORIES(git2util PRIVATE ${LIBGIT2_UTIL_INCLUDES} PUBLIC ${libgit2_SOURCE_DIR}/include)
TARGET_INCLUDE_DIRECTORIES(git2util SYSTEM PRIVATE ${LIBGIT2_UTIL_SYSTEM_INCLUDES})

SET(LIBGIT2_UTIL_OBJECTS ${UTIL_OBJECTS} PARENT_SCOPE)

