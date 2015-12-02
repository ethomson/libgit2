/*
* Copyright (C) the libgit2 contributors. All rights reserved.
*
* This file is part of libgit2, distributed under the GNU GPL v2 with
* a Linking Exception. For full terms see the included COPYING file.
*/
#ifndef INCLUDE_strnmap_h__
#define INCLUDE_strnmap_h__

#include "common.h"

#define kmalloc git__malloc
#define kcalloc git__calloc
#define krealloc git__realloc
#define kreallocarray git__reallocarray
#define kfree git__free
#include "khash.h"

__KHASH_TYPE(str, const char *, void *)
typedef khash_t(str) git_strnmap;
typedef khiter_t git_strnmap_iter;

#define GIT__USE_STRNMAP \
	__KHASH_IMPL(str, static kh_inline, const char *, void *, 1, kh_strn_hash_func, kh_strn_hash_equal)

#define git_strnmap_alloc(hp) \
	((*(hp) = kh_init(str)) == NULL) ? giterr_set_oom(), -1 : 0

#define git_strnmap_free(h)  kh_destroy(str, h), h = NULL
#define git_strnmap_clear(h) kh_clear(str, h)

#define git_strnmap_num_entries(h) kh_size(h)

#define git_strnmap_lookup_index(h, k)  kh_get(str, h, k)
#define git_strnmap_valid_index(h, idx) (idx != kh_end(h))

#define git_strnmap_exists(h, k) (kh_get(str, h, k) != kh_end(h))
#define git_strnmap_has_data(h, idx) kh_exist(h, idx)

#define git_strnmap_key(h, idx)             kh_key(h, idx)
#define git_strnmap_value_at(h, idx)        kh_val(h, idx)
#define git_strnmap_set_value_at(h, idx, v) kh_val(h, idx) = v
#define git_strnmap_delete_at(h, idx)       kh_del(str, h, idx)

#define git_strnmap_insert(h, key, val, rval) do { \
	khiter_t __pos = kh_put(str, h, key, &rval); \
	if (rval >= 0) { \
		if (rval == 0) kh_key(h, __pos) = key; \
		kh_val(h, __pos) = val; \
	} } while (0)

#define git_strnmap_insert2(h, key, val, oldv, rval) do { \
	khiter_t __pos = kh_put(str, h, key, &rval); \
	if (rval >= 0) { \
		if (rval == 0) { \
			oldv = kh_val(h, __pos); \
			kh_key(h, __pos) = key; \
		} else { oldv = NULL; } \
		kh_val(h, __pos) = val; \
	} } while (0)

#define git_strnmap_delete(h, key) do { \
	khiter_t __pos = git_strmap_lookup_index(h, key); \
	if (git_strmap_valid_index(h, __pos)) \
		git_strmap_delete_at(h, __pos); } while (0)

#define git_strnmap_foreach		kh_foreach
#define git_strnmap_foreach_value	kh_foreach_value

#define git_strnmap_begin		kh_begin
#define git_strnmap_end		kh_end

#endif
