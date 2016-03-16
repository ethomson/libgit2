/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "iterator.h"
#include "tree.h"
#include "index.h"
#include "ignore.h"
#include "buffer.h"
#include "submodule.h"
#include "object_api.h"
#include <ctype.h>

#define ITERATOR_SET_CB(P,NAME_LC) do { \
	(P)->cb.current = NAME_LC ## _iterator__current; \
	(P)->cb.advance = NAME_LC ## _iterator__advance; \
	(P)->cb.advance_into = NAME_LC ## _iterator__advance_into; \
	(P)->cb.reset   = NAME_LC ## _iterator__reset; \
	(P)->cb.reset_range = NAME_LC ## _iterator__reset_range; \
	(P)->cb.at_end  = NAME_LC ## _iterator__at_end; \
	(P)->cb.free    = NAME_LC ## _iterator__free; \
	} while (0)

#define ITERATOR_CASE_FLAGS \
	(GIT_ITERATOR_IGNORE_CASE | GIT_ITERATOR_DONT_IGNORE_CASE)

#define ITERATOR_BASE_INIT(P,NAME_LC,NAME_UC,REPO) do { \
	(P)->base.type    = GIT_ITERATOR_TYPE_ ## NAME_UC; \
	(P)->base.cb      = &(P)->cb; \
	ITERATOR_SET_CB(P,NAME_LC); \
	(P)->base.repo    = (REPO); \
	(P)->base.start   = options && options->start ? \
		git__strdup(options->start) : NULL; \
	(P)->base.end     = options && options->end ? \
		git__strdup(options->end) : NULL; \
	if ((options && options->start && !(P)->base.start) || \
		(options && options->end && !(P)->base.end)) { \
		git__free(P); return -1; } \
	(P)->base.strcomp = git__strcmp; \
	(P)->base.strncomp = git__strncmp; \
	(P)->base.prefixcomp = git__prefixcmp; \
	(P)->base.flags = options ? options->flags & ~ITERATOR_CASE_FLAGS : 0; \
	if ((P)->base.flags & GIT_ITERATOR_DONT_AUTOEXPAND) \
		(P)->base.flags |= GIT_ITERATOR_INCLUDE_TREES; \
	if (options && options->pathlist.count && \
		iterator_pathlist__init(&P->base, &options->pathlist) < 0) { \
		git__free(P); return -1; } \
	} while (0)

#define GIT_ITERATOR_FIRST_ACCESS   (1 << 15)
#define GIT_ITERATOR_HONOR_IGNORES  (1 << 16)
#define GIT_ITERATOR_IGNORE_DOT_GIT (1 << 17)

#define iterator__flag(I,F) ((((git_iterator *)(I))->flags & GIT_ITERATOR_ ## F) != 0)
#define iterator__ignore_case(I)       iterator__flag(I,IGNORE_CASE)
#define iterator__include_trees(I)     iterator__flag(I,INCLUDE_TREES)
#define iterator__dont_autoexpand(I)   iterator__flag(I,DONT_AUTOEXPAND)
#define iterator__do_autoexpand(I)    !iterator__flag(I,DONT_AUTOEXPAND)
#define iterator__include_conflicts(I) iterator__flag(I,INCLUDE_CONFLICTS)
#define iterator__has_been_accessed(I) iterator__flag(I,FIRST_ACCESS)
#define iterator__honor_ignores(I)     iterator__flag(I,HONOR_IGNORES)
#define iterator__ignore_dot_git(I)    iterator__flag(I,IGNORE_DOT_GIT)

#define iterator__end(I) ((git_iterator *)(I))->end
#define iterator__past_end(I,PATH) \
	(iterator__end(I) && ((git_iterator *)(I))->prefixcomp((PATH),iterator__end(I)) > 0)


typedef enum {
	ITERATOR_PATHLIST_NONE = 0,
	ITERATOR_PATHLIST_MATCH = 1,
	ITERATOR_PATHLIST_MATCH_DIRECTORY = 2,
	ITERATOR_PATHLIST_MATCH_CHILD = 3,
} iterator_pathlist__match_t;

static int iterator_pathlist__init(git_iterator *iter, git_strarray *pathspec)
{
	size_t i;

	if (git_vector_init(&iter->pathlist, pathspec->count,
			(git_vector_cmp)iter->strcomp) < 0)
		return -1;

	for (i = 0; i < pathspec->count; i++) {
		if (!pathspec->strings[i])
			continue;

		if (git_vector_insert(&iter->pathlist, pathspec->strings[i]) < 0)
			return -1;
	}

	git_vector_sort(&iter->pathlist);

	return 0;
}

static iterator_pathlist__match_t iterator_pathlist__match(
	git_iterator *iter, const char *path, size_t path_len)
{
	const char *p;
	size_t idx;
	int error;

	error = git_vector_bsearch2(&idx, &iter->pathlist,
		(git_vector_cmp)iter->strcomp, path);

	if (error == 0)
		return ITERATOR_PATHLIST_MATCH;

	/* at this point, the path we're examining may be a directory (though we
	 * don't know that yet, since we're avoiding a stat unless it's necessary)
	 * so see if the pathlist contains a file beneath this directory.
	 */
	while ((p = git_vector_get(&iter->pathlist, idx)) != NULL) {
		if (iter->prefixcomp(p, path) != 0)
			break;

		/* an exact match would have been matched by the bsearch above */
		assert(p[path_len]);

		/* is this a literal directory entry (eg `foo/`) or a file beneath */
		if (p[path_len] == '/') {
			return (p[path_len+1] == '\0') ?
				ITERATOR_PATHLIST_MATCH_DIRECTORY :
				ITERATOR_PATHLIST_MATCH_CHILD;
		}

		if (p[path_len] > '/')
			break;

		idx++;
	}

	return ITERATOR_PATHLIST_NONE;
}

static void iterator_pathlist_walk__reset(git_iterator *iter)
{
	iter->pathlist_walk_idx = 0;
}

/* walker for the index iterator that allows it to walk the sorted pathlist
 * entries alongside the sorted index entries.  the `iter->pathlist_walk_idx`
 * stores the starting position for subsequent calls, the position is advanced
 * along with the index iterator, with a special case for handling directories
 * in the pathlist that are specified without trailing '/'.  (eg, `foo`).
 * we do not advance over these entries until we're certain that the index
 * iterator will not ask us for a file beneath that directory (eg, `foo/bar`).
 */
static bool iterator_pathlist_walk__contains(git_iterator *iter, const char *path)
{
	size_t i;
	char *p;
	size_t p_len;
	int cmp;

	for (i = iter->pathlist_walk_idx; i < iter->pathlist.length; i++) {
		p = iter->pathlist.contents[i];
		p_len = strlen(p);

		/* see if the pathlist entry is a prefix of this path */
		cmp = iter->strncomp(p, path, p_len);

		/* this pathlist entry sorts before the given path, try the next */
		if (!p_len || cmp < 0)
			iter->pathlist_walk_idx++;

		/* this pathlist sorts after the given path, no match. */
		else if (cmp > 0)
			return false;

		/* match!  an exact match (`foo` vs `foo`), the path is a child of an
		 * explicit directory in the pathlist (`foo/` vs `foo/bar`) or the path
		 * is a child of an entry in the pathlist (`foo` vs `foo/bar`)
		 */
		else if (path[p_len] == '\0' || p[p_len - 1] == '/' || path[p_len] == '/')
			return true;

		/* only advance the start index for future callers if we know that we
		 * will not see a child of this path.  eg, a pathlist entry `foo` is
		 * a prefix for `foo.txt` and `foo/bar`.  don't advance the start
		 * pathlist index when we see `foo.txt` or we would miss a subsequent
		 * inspection of `foo/bar`.  only advance when there are no more
		 * potential children.
		 */
		else if (path[p_len] > '/')
			iter->pathlist_walk_idx++;
	}

	return false;
}

static void iterator_pathlist__update_ignore_case(git_iterator *iter)
{
	git_vector_set_cmp(&iter->pathlist, (git_vector_cmp)iter->strcomp);
	git_vector_sort(&iter->pathlist);

	iter->pathlist_walk_idx = 0;
}


static int iterator__reset_range(
	git_iterator *iter, const char *start, const char *end)
{
	if (iter->start)
		git__free(iter->start);

	if (start) {
		iter->start = git__strdup(start);
		GITERR_CHECK_ALLOC(iter->start);
	}

	if (iter->end)
		git__free(iter->end);

	if (end) {
		iter->end = git__strdup(end);
		GITERR_CHECK_ALLOC(iter->end);
	}

	iter->flags &= ~GIT_ITERATOR_FIRST_ACCESS;

	return 0;
}

int git_iterator_set_ignore_case(git_iterator *iter, bool ignore_case)
{
	if (ignore_case) {
		iter->flags = (iter->flags | GIT_ITERATOR_IGNORE_CASE);
		
		iter->strcomp = git__strcasecmp;
		iter->strncomp = git__strncasecmp;
		iter->prefixcomp = git__prefixcmp_icase;
		iter->entry_srch = git_index_entry_isrch;
	} else {
		iter->flags = (iter->flags & ~GIT_ITERATOR_IGNORE_CASE);
		
		iter->strcomp = git__strcmp;
		iter->strncomp = git__strncmp;
		iter->prefixcomp = git__prefixcmp;
		iter->entry_srch = git_index_entry_srch;
	}
	
	iterator_pathlist__update_ignore_case(iter);

	return 0;
}

static int iterator__update_ignore_case(
	git_iterator *iter,
	git_iterator_flag_t flags)
{
	bool ignore_case;
	int error;

	if ((flags & GIT_ITERATOR_IGNORE_CASE) != 0)
		ignore_case = true;
	else if ((flags & GIT_ITERATOR_DONT_IGNORE_CASE) != 0)
		ignore_case = false;
	else {
		git_index *index;

		if ((error = git_repository_index__weakptr(&index, iter->repo)) < 0)
			return error;

		ignore_case = (index->ignore_case == 1);
	}

	return git_iterator_set_ignore_case(iter, ignore_case);
}

GIT_INLINE(void) iterator__clear_entry(const git_index_entry **entry)
{
	if (entry) *entry = NULL;
}


static int iterator_range_init(
	git_iterator *iter, const char *start, const char *end)
{
	if (start && *start) {
		iter->start = git__strdup(start);
		GITERR_CHECK_ALLOC(iter->start);
		
		iter->start_len = strlen(iter->start);
	}

	if (end && *end) {
		iter->end = git__strdup(end);
		GITERR_CHECK_ALLOC(iter->end);
		
		iter->end_len = strlen(iter->end);
	}

	iter->started = (iter->start == NULL);
	iter->ended = false;

	return 0;
}

static void iterator_range_free(git_iterator *iter)
{
	if (iter->start) {
		git__free(iter->start);
		iter->start = NULL;
		iter->start_len = 0;
	}

	if (iter->end) {
		git__free(iter->end);
		iter->end = NULL;
		iter->end_len = 0;
	}
}

static int iterator_range_reset(
	git_iterator *iter, const char *start, const char *end)
{
	iterator_range_free(iter);
	return iterator_range_init(iter, start, end);
}

static int iterator_pathlist_init(git_iterator *iter, git_strarray *pathlist)
{
	size_t i;

	if (git_vector_init(&iter->pathlist, pathlist->count,
		(git_vector_cmp)iter->strcomp) < 0)
		return -1;

	for (i = 0; i < pathlist->count; i++) {
		if (!pathlist->strings[i])
			continue;

		if (git_vector_insert(&iter->pathlist, pathlist->strings[i]) < 0)
			return -1;
	}

	git_vector_sort(&iter->pathlist);
	return 0;
}

static int iterator_init_common(
	git_iterator *iter,
	git_repository *repo,
	git_iterator_options *given_opts)
{
	static git_iterator_options default_opts = GIT_ITERATOR_OPTIONS_INIT;
	git_iterator_options *options = given_opts ? given_opts : &default_opts;
	bool ignore_case;
	int precompose;
	int error;

	iter->repo = repo;
	iter->flags = options->flags;

	if ((iter->flags & GIT_ITERATOR_IGNORE_CASE) != 0) {
		ignore_case = true;
	} else if ((iter->flags & GIT_ITERATOR_DONT_IGNORE_CASE) != 0) {
		ignore_case = false;
	} else if (repo) {
		git_index *index;

		if ((error = git_repository_index__weakptr(&index, iter->repo)) < 0)
			return error;

		ignore_case = !!index->ignore_case;

		if (ignore_case == 1)
			iter->flags |= GIT_ITERATOR_IGNORE_CASE;
		else
			iter->flags |= GIT_ITERATOR_DONT_IGNORE_CASE;
	} else {
		ignore_case = false;
	}

	/* try to look up precompose and set flag if appropriate */
	if (repo &&
		!(iter->flags & GIT_ITERATOR_PRECOMPOSE_UNICODE) != 0 &&
		!(iter->flags & GIT_ITERATOR_DONT_PRECOMPOSE_UNICODE)) {

		if (git_repository__cvar(&precompose, repo, GIT_CVAR_PRECOMPOSE) < 0)
			giterr_clear();
		else if (precompose)
			iter->flags |= GIT_ITERATOR_PRECOMPOSE_UNICODE;
	}

	if ((iter->flags & GIT_ITERATOR_DONT_AUTOEXPAND))
		iter->flags |= GIT_ITERATOR_INCLUDE_TREES;

	iter->strcomp = ignore_case ? git__strcasecmp : git__strcmp;
	iter->strncomp = ignore_case ? git__strncasecmp : git__strncmp;
	iter->prefixcomp = ignore_case ? git__prefixcmp_icase : git__prefixcmp;
	iter->entry_srch = ignore_case ? git_index_entry_srch : git_index_entry_isrch;

	if ((error = iterator_range_init(iter, options->start, options->end)) < 0 ||
		(error = iterator_pathlist_init(iter, &options->pathlist)) < 0)
		return error;

	return 0;
}

static void iterator_clear(git_iterator *iter)
{
	iter->started = false;
	iter->ended = false;
	iter->pathlist_walk_idx = 0;
	iter->flags &= ~GIT_ITERATOR_FIRST_ACCESS;
}

GIT_INLINE(bool) iterator_has_started(git_iterator *iter, const char *path)
{
	size_t path_len;

	if (iter->start == NULL || iter->started == true)
		return true;

	/* the starting path is generally a prefix - we have started once we
	 * are prefixed by this path
	 */
	iter->started = (iter->prefixcomp(path, iter->start) >= 0);

	/* if, however, our current path is a directory, and our starting path
	 * is _beneath_ that directory, then recurse into the directory (even
	 * though we have not yet "started")
	 */
	if (!iter->started &&
		(path_len = strlen(path)) > 0 && path[path_len-1] == '/' &&
		iter->strncomp(path, iter->start, path_len) == 0)
		return true;

	return iter->started;
}

GIT_INLINE(bool) iterator_has_ended(git_iterator *iter, const char *path)
{
	if (iter->end == NULL || iter->ended == true)
		return false;

	iter->ended = (iter->prefixcomp(path, iter->end) > 0);
	return iter->ended;
}

/* walker for the index iterator that allows it to walk the sorted pathlist
 * entries alongside sorted iterator entries.
 */
static bool iterator_pathlist_next_is(git_iterator *iter, const char *path)
{
	char *p;
	size_t path_len, i;
	int cmp;
	
	if (iter->pathlist.length == 0)
		return true;

	path_len = strlen(path);
	
	for (i = iter->pathlist_walk_idx; i < iter->pathlist.length; i++) {
		p = iter->pathlist.contents[i];
		
		/* see if the pathlist entry is a prefix of this path */
		cmp = iter->strncomp(p, path, path_len);

		/* this pathlist entry sorts before the given path, try the next */
		if (cmp < 0) {
			iter->pathlist_walk_idx++;
			continue;
		}

		/* this pathlist sorts after the given path, no match. */
		else if (cmp > 0) {
			break;
		}

		/* if this is an exact match then it is to be included */
		if (p[path_len] == '\0')
			return true;

		/* this is not an exact match - is the path we're examining a
		 * directory?  if so then we need to recurse into it.
		 */
		if (path_len && p[path_len-1] == '/')
			return true;

		/* the pathlist entry is longer than the given path and thus sorts
		 * after it.  stop.
		 */
		break;
	}
	
	return false;
}

typedef enum {
	ITERATOR_PATHLIST_NOT_FOUND = 0,
	ITERATOR_PATHLIST_IS_FILE = 1,
	ITERATOR_PATHLIST_IS_DIR = 2,
	ITERATOR_PATHLIST_IS_PARENT = 3,
	ITERATOR_PATHLIST_FULL = 4,
} iterator_pathlist_search_t;

static iterator_pathlist_search_t iterator_pathlist_search(
	git_iterator *iter, const char *path, size_t path_len)
{
	const char *p;
	size_t idx;
	int error;
	
	error = git_vector_bsearch2(&idx, &iter->pathlist,
		(git_vector_cmp)iter->strcomp, path);

	/* the given path was found in the pathlist.  since the pathlist only
	 * matches directories when they're suffixed with a '/', analyze the
	 * path string to determine whether it's a directory or not.
	 */
	if (error == 0) {
		if (path_len && path[path_len-1] == '/')
			return ITERATOR_PATHLIST_IS_DIR;

		return ITERATOR_PATHLIST_IS_FILE;
	}

	/* at this point, the path we're examining may be a directory (though we
	 * don't know that yet, since we're avoiding a stat unless it's necessary)
	 * so walk the pathlist looking for the given path with a '/' after it,
	 */
	while ((p = git_vector_get(&iter->pathlist, idx)) != NULL) {
		if (iter->prefixcomp(p, path) != 0)
			break;
		
		/* an exact match would have been matched by the bsearch above */
		assert(p[path_len]);

		/* is this a literal directory entry (eg `foo/`) or a file beneath */
		if (p[path_len] == '/') {
			return (p[path_len+1] == '\0') ?
				ITERATOR_PATHLIST_IS_DIR :
				ITERATOR_PATHLIST_IS_PARENT;
		}
		
		if (p[path_len] > '/')
			break;
		
		idx++;
	}
	
	return ITERATOR_PATHLIST_NOT_FOUND;
}

/* Empty iterator */

static int empty_iterator__noop(const git_index_entry **e, git_iterator *i)
{
	GIT_UNUSED(i);
	iterator__clear_entry(e);
	return GIT_ITEROVER;
}

static int empty_iterator__reset(git_iterator *i)
{
	GIT_UNUSED(i);
	return 0;
}

static int empty_iterator__reset_range(
	git_iterator *i, const char *s, const char *e)
{
	GIT_UNUSED(i); GIT_UNUSED(s); GIT_UNUSED(e);
	return 0;
}

static int empty_iterator__at_end(git_iterator *i)
{
	GIT_UNUSED(i);
	return 1;
}

static void empty_iterator__free(git_iterator *i)
{
	GIT_UNUSED(i);
}

typedef struct {
	git_iterator base;
	git_iterator_callbacks cb;
} empty_iterator;

int git_iterator_for_nothing(
	git_iterator **iter,
	git_iterator_options *options)
{
	empty_iterator *i = git__calloc(1, sizeof(empty_iterator));
	GITERR_CHECK_ALLOC(i);

#define empty_iterator__current empty_iterator__noop
#define empty_iterator__advance empty_iterator__noop
#define empty_iterator__advance_into empty_iterator__noop

	ITERATOR_BASE_INIT(i, empty, EMPTY, NULL);

	if (options && (options->flags & GIT_ITERATOR_IGNORE_CASE) != 0)
		i->base.flags |= GIT_ITERATOR_IGNORE_CASE;

	*iter = (git_iterator *)i;
	return 0;
}

/* Tree iterator */

typedef struct {
	git_tree_entry *tree_entry;
	const char *parent_path;
} tree_iterator_entry;

typedef struct {
	git_tree *tree;

	/* a sorted list of the entries for this frame (folder), these are
	 * actually pointers to the iterator's entry pool.
	 */
	git_vector entries;
	tree_iterator_entry *current;

	size_t next_idx;

	/* the path to this particular frame (folder); on case insensitive
	 * iterations, we also have an array of other paths that we were
	 * case insensitively equal to this one, whose contents we have
	 * coalesced into this frame.  a child `tree_iterator_entry` will
	 * contain a pointer to its actual parent path.
	 */
	git_buf path;
	git_array_t(git_buf) similar_paths;
} tree_iterator_frame;

typedef struct {
	git_iterator base;
	git_tree *root;
	git_array_t(tree_iterator_frame) frames;

	git_index_entry entry;
	git_buf entry_path;

	/* a pool of entries to reduce the number of allocations */
	git_pool entry_pool;
} tree_iterator;

GIT_INLINE(tree_iterator_frame *) tree_iterator_parent_frame(
	tree_iterator *iter)
{
	return iter->frames.size > 1 ?
		&iter->frames.ptr[iter->frames.size-2] : NULL;
}

GIT_INLINE(tree_iterator_frame *) tree_iterator_current_frame(
	tree_iterator *iter)
{
	return iter->frames.size ? &iter->frames.ptr[iter->frames.size-1] : NULL;
}

GIT_INLINE(int) tree_entry_cmp(
	const git_tree_entry *a, const git_tree_entry *b, bool icase)
{
	return git_path_cmp(
		a->filename, a->filename_len, a->attr == GIT_FILEMODE_TREE,
		b->filename, b->filename_len, b->attr == GIT_FILEMODE_TREE,
		icase ? git__strncasecmp : git__strncmp);
}

GIT_INLINE(int) tree_iterator_entry_cmp(const void *ptr_a, const void *ptr_b)
{
	const tree_iterator_entry *a = (const tree_iterator_entry *)ptr_a;
	const tree_iterator_entry *b = (const tree_iterator_entry *)ptr_b;

	return tree_entry_cmp(a->tree_entry, b->tree_entry, false);
}

GIT_INLINE(int) tree_iterator_entry_cmp_icase(
	const void *ptr_a, const void *ptr_b)
{
	const tree_iterator_entry *a = (const tree_iterator_entry *)ptr_a;
	const tree_iterator_entry *b = (const tree_iterator_entry *)ptr_b;

	return tree_entry_cmp(a->tree_entry, b->tree_entry, true);
}

static int tree_iterator_entry_sort_icase(const void *ptr_a, const void *ptr_b)
{
	const tree_iterator_entry *a = (const tree_iterator_entry *)ptr_a;
	const tree_iterator_entry *b = (const tree_iterator_entry *)ptr_b;

	int c = tree_entry_cmp(a->tree_entry, b->tree_entry, true);

	/* stabilize the sort order for filenames that are (case insensitively)
	 * the same by examining the parent path (case sensitively) before
	 * falling back to a case sensitive sort of the filename.
	 */
	if (!c && a->parent_path != b->parent_path)
		c = git__strcmp(a->parent_path, b->parent_path);

	if (!c)
		c = tree_entry_cmp(a->tree_entry, b->tree_entry, false);

	return c;
}

static int tree_iterator_compute_path(
	git_buf *out,
	tree_iterator_entry *entry)
{
	git_buf_clear(out);
	
	if (entry->parent_path)
		git_buf_joinpath(out, entry->parent_path, entry->tree_entry->filename);
	else
		git_buf_puts(out, entry->tree_entry->filename);
	
	if (git_tree_entry__is_tree(entry->tree_entry))
		git_buf_putc(out, '/');
	
	if (git_buf_oom(out))
		return -1;
	
	return 0;
}

static int tree_iterator_frame_init(
	tree_iterator *iter,
	git_tree *tree,
	tree_iterator_entry *frame_entry)
{
	tree_iterator_frame *new_frame = NULL;
	tree_iterator_entry *new_entry;
	git_tree *dup = NULL;
	git_tree_entry *tree_entry;
	git_vector_cmp cmp;
	size_t i;
	int error = 0;

	new_frame = git_array_alloc(iter->frames);
	GITERR_CHECK_ALLOC(new_frame);
	
	memset(new_frame, 0, sizeof(tree_iterator_frame));

	if ((error = git_tree_dup(&dup, tree)) < 0)
		goto done;

	memset(new_frame, 0x0, sizeof(tree_iterator_frame));
	new_frame->tree = dup;

	if (frame_entry &&
		(error = tree_iterator_compute_path(&new_frame->path, frame_entry)) < 0)
		goto done;

	cmp = iterator__ignore_case(&iter->base) ?
		tree_iterator_entry_sort_icase : NULL;

	if ((error = git_vector_init(
		&new_frame->entries, dup->entries.length, cmp)) < 0)
		goto done;

	git_vector_foreach(&dup->entries, i, tree_entry) {
		new_entry = git_pool_malloc(&iter->entry_pool, 1);
		GITERR_CHECK_ALLOC(new_entry);

		new_entry->tree_entry = tree_entry;
		new_entry->parent_path = new_frame->path.ptr;

		if ((error = git_vector_insert(&new_frame->entries, new_entry)) < 0)
			goto done;
	}

	git_vector_set_sorted(&new_frame->entries,
		!iterator__ignore_case(&iter->base));

done:
	if (error < 0) {
		git_tree_free(dup);
		git_array_pop(iter->frames);
	}

	return error;
}

GIT_INLINE(tree_iterator_entry *) tree_iterator_current_entry(
	tree_iterator_frame *frame)
{
	return frame->current;
}

GIT_INLINE(int) tree_iterator_frame_push_neighbors(
	tree_iterator *iter,
	tree_iterator_frame *parent_frame,
	tree_iterator_frame *frame,
	const char *filename)
{
	tree_iterator_entry *entry, *new_entry;
	git_tree *tree = NULL;
	git_tree_entry *tree_entry;
	git_buf *path;
	size_t new_size, i;
	int error = 0;

	while (parent_frame->next_idx < parent_frame->entries.length) {
		entry = parent_frame->entries.contents[parent_frame->next_idx];

		if (strcasecmp(filename, entry->tree_entry->filename) != 0)
			break;

		if ((error = git_tree_lookup(&tree,
			iter->base.repo, &entry->tree_entry->oid)) < 0)
			break;

		path = git_array_alloc(parent_frame->similar_paths);
		GITERR_CHECK_ALLOC(path);
		
		memset(path, 0, sizeof(git_buf));

		if ((error = tree_iterator_compute_path(path, entry)) < 0)
			break;

		GITERR_CHECK_ALLOC_ADD(&new_size,
			frame->entries.length, tree->entries.length);
		git_vector_size_hint(&frame->entries, new_size);

		git_vector_foreach(&tree->entries, i, tree_entry) {
			new_entry = git_pool_malloc(&iter->entry_pool, 1);
			GITERR_CHECK_ALLOC(new_entry);
			
			new_entry->tree_entry = tree_entry;
			new_entry->parent_path = path->ptr;

			if ((error = git_vector_insert(&frame->entries, new_entry)) < 0)
				break;
		}

		if (error)
			break;

		parent_frame->next_idx++;
	}

	return error;
}

GIT_INLINE(int) tree_iterator_frame_push(
	tree_iterator *iter, tree_iterator_entry *entry)
{
	tree_iterator_frame *parent_frame, *frame;
	git_tree *tree = NULL;
	int error;

	if ((error = git_tree_lookup(&tree,
			iter->base.repo, &entry->tree_entry->oid)) < 0 ||
		(error = tree_iterator_frame_init(iter, tree, entry)) < 0)
		goto done;

	parent_frame = tree_iterator_parent_frame(iter);
	frame = tree_iterator_current_frame(iter);

	/* if we're case insensitive, then we may have another directory that
	 * is (case insensitively) equal to this one.  coalesce those children
	 * into this tree.
	 */
	if (iterator__ignore_case(&iter->base))
		error = tree_iterator_frame_push_neighbors(iter,
			parent_frame, frame, entry->tree_entry->filename);

done:
	git_tree_free(tree);
	return error;
}

static void tree_iterator_frame_pop(tree_iterator *iter)
{
	tree_iterator_frame *frame;

	assert(iter->frames.size);

	frame = git_array_pop(iter->frames);

	git_vector_free(&frame->entries);
	git_tree_free(frame->tree);
}

static int tree_iterator_current(
	const git_index_entry **out, git_iterator *i)
{
	tree_iterator *iter = (tree_iterator *)i;

	if (!iterator__has_been_accessed(i))
		return iter->base.cb->advance(out, i);

	if (!iter->frames.size) {
		*out = NULL;
		return GIT_ITEROVER;
	}

	*out = &iter->entry;
	return 0;
}

static void tree_iterator_set_current(
	tree_iterator *iter,
	tree_iterator_frame *frame,
	tree_iterator_entry *entry)
{
	git_tree_entry *tree_entry = entry->tree_entry;

	frame->current = entry;

	memset(&iter->entry, 0x0, sizeof(git_index_entry));

	iter->entry.mode = tree_entry->attr;
	iter->entry.path = iter->entry_path.ptr;
	git_oid_cpy(&iter->entry.id, &tree_entry->oid);
}

static int tree_iterator_advance(const git_index_entry **out, git_iterator *i)
{
	tree_iterator *iter = (tree_iterator *)i;
	int error = 0;
	
	iter->base.flags |= GIT_ITERATOR_FIRST_ACCESS;

	/* examine tree entries until we find the next one to return */
	while (true) {
		tree_iterator_entry *prev_entry, *entry;
		tree_iterator_frame *frame;
		bool is_tree;

		if ((frame = tree_iterator_current_frame(iter)) == NULL) {
			error = GIT_ITEROVER;
			break;
		}

		/* no more entries in this frame.  pop the frame out */
		if (frame->next_idx == frame->entries.length) {
			tree_iterator_frame_pop(iter);
			continue;
		}
		
		/* we may have coalesced the contents of case-insensitively same-named
		 * directories, so do the sort now.
		 */
		if (frame->next_idx == 0 && !git_vector_is_sorted(&frame->entries))
			git_vector_sort(&frame->entries);

		/* we have more entries in the current frame, that's our next entry */
		prev_entry = tree_iterator_current_entry(frame);
		entry = frame->entries.contents[frame->next_idx];
		frame->next_idx++;

		/* we can have collisions when iterating case insensitively.  (eg,
		 * 'A/a' and 'a/A').  squash this one if it's already been seen.
		 */
		if (iterator__ignore_case(&iter->base) &&
			prev_entry &&
			tree_iterator_entry_cmp_icase(prev_entry, entry) == 0)
			continue;

		if ((error = tree_iterator_compute_path(&iter->entry_path, entry)) < 0)
			break;

		/* if this path is before our start, advance over this entry */
		if (!iterator_has_started(&iter->base, iter->entry_path.ptr))
			continue;

		/* if this path is after our end, stop */
		if (iterator_has_ended(&iter->base, iter->entry_path.ptr)) {
			error = GIT_ITEROVER;
			break;
		}

		/* if we have a list of paths we're interested in, examine it */
		if (!iterator_pathlist_next_is(&iter->base, iter->entry_path.ptr))
			continue;

		is_tree = git_tree_entry__is_tree(entry->tree_entry);

		/* if we are *not* including trees then advance over this entry */
		if (is_tree && !iterator__include_trees(iter)) {

			/* if we've found a tree (and are not returning it to the caller)
			 * and we are autoexpanding, then we want to return the first
			 * child.  push the new directory and advance.
			 */
			if (iterator__do_autoexpand(iter)) {
				if ((error = tree_iterator_frame_push(iter, entry)) < 0)
					break;
			}

			continue;
		}

		tree_iterator_set_current(iter, frame, entry);

		/* if we are autoexpanding, then push this as a new frame, so that
		 * the next call to `advance` will dive into this directory.
		 */
		if (is_tree && iterator__do_autoexpand(iter))
			error = tree_iterator_frame_push(iter, entry);

		break;
	}
	
	if (out)
		*out = (error == 0) ? &iter->entry : NULL;

	return error;
}

static int tree_iterator_advance_into(
	const git_index_entry **out, git_iterator *i)
{
	tree_iterator *iter = (tree_iterator *)i;
    tree_iterator_frame *frame;
	tree_iterator_entry *prev_entry;
	int error;

	if (out)
		*out = NULL;

	if ((frame = tree_iterator_current_frame(iter)) == NULL)
		return GIT_ITEROVER;

	/* get the last seen entry */
	prev_entry = tree_iterator_current_entry(frame);

	/* it's legal to call advance_into when auto-expand is on.  in this case,
	 * we will have pushed a new (empty) frame on to the stack for this
	 * new directory.  since it's empty, its current_entry should be null.
	 */
	assert(iterator__do_autoexpand(i) ^ (prev_entry != NULL));

	if (prev_entry) {
		if (!git_tree_entry__is_tree(prev_entry->tree_entry))
			return 0;

		if ((error = tree_iterator_frame_push(iter, prev_entry)) < 0)
			return error;
	}

	/* we've advanced into the directory in question, let advance
	 * find the first entry
	 */
	return tree_iterator_advance(out, i);
}

static void tree_iterator_clear(tree_iterator *iter)
{
	while (iter->frames.size)
		tree_iterator_frame_pop(iter);

	git_array_clear(iter->frames);

	git_pool_clear(&iter->entry_pool);
	git_buf_clear(&iter->entry_path);
	
	iterator_clear(&iter->base);
}

static int tree_iterator_init(tree_iterator *iter)
{
	int error;

	if ((error = tree_iterator_frame_init(iter, iter->root, NULL)) < 0)
		return error;

	iter->base.flags &= ~GIT_ITERATOR_FIRST_ACCESS;

	git_pool_init(&iter->entry_pool, sizeof(tree_iterator_entry));
	
	return 0;
}

static int tree_iterator_reset(git_iterator *i)
{
	tree_iterator *iter = (tree_iterator *)i;

	tree_iterator_clear(iter);
	return tree_iterator_init(iter);
}

static int tree_iterator_reset_range(
	git_iterator *i, const char *start, const char *end)
{
	if (iterator_range_reset(i, start, end) < 0)
		return -1;

	return tree_iterator_reset(i);
}

static int tree_iterator_at_end(git_iterator *i)
{
	tree_iterator *iter = (tree_iterator *)i;

	return (iter->frames.size == 0);
}

static void tree_iterator_free(git_iterator *i)
{
	tree_iterator *iter = (tree_iterator *)i;

	tree_iterator_clear(iter);

	git_tree_free(iter->root);
	git_buf_free(&iter->entry_path);
}

int git_iterator_for_tree(
	git_iterator **out,
	git_tree *tree,
	git_iterator_options *options)
{
	tree_iterator *iter;
	git_tree *root = NULL;
	int error;

	static git_iterator_callbacks callbacks = {
		tree_iterator_current,
		tree_iterator_advance,
		tree_iterator_advance_into,
		NULL, /* advance_over */
		tree_iterator_reset,
		tree_iterator_reset_range,
		tree_iterator_at_end,
		tree_iterator_free
	};

	*out = NULL;
	
	if (tree == NULL)
		return git_iterator_for_nothing(out, options);

	iter = git__calloc(1, sizeof(tree_iterator));
	GITERR_CHECK_ALLOC(iter);

	iter->base.type = GIT_ITERATOR_TYPE_TREE;
	iter->base.cb = &callbacks;

	if ((error = iterator_init_common(&iter->base,
			git_tree_owner(tree), options)) < 0 ||
		(error = git_tree_dup(&root, tree)) < 0)
		goto on_error;

	iter->root = root;

	if ((error = tree_iterator_init(iter)) < 0)
		goto on_error;

	*out = &iter->base;
	return 0;

on_error:
	git_iterator_free(&iter->base);
	git_tree_free(root);
	return error;
}

int git_iterator_current_tree_entry(
	const git_tree_entry **tree_entry, git_iterator *i)
{
	tree_iterator *iter;

	assert(i->type == GIT_ITERATOR_TYPE_TREE);

	iter = (tree_iterator *)i;

	tree_iterator_frame *frame = tree_iterator_current_frame(iter);
	tree_iterator_entry *entry = tree_iterator_current_entry(frame);

	*tree_entry = entry->tree_entry;
	return 0;
}

int git_iterator_current_parent_tree(
	const git_tree **parent_tree, git_iterator *i, size_t depth)
{
	tree_iterator *iter;
	tree_iterator_frame *frame;

	assert(i->type == GIT_ITERATOR_TYPE_TREE);

	iter = (tree_iterator *)i;

	assert(depth < iter->frames.size);
	frame = &iter->frames.ptr[iter->frames.size-depth-1];

	*parent_tree = frame->tree;
	return 0;
}

/* Filesystem iterator */

typedef struct {
	struct stat st;
	size_t path_len;
	iterator_pathlist_search_t match;
	char path[GIT_FLEX_ARRAY];
} filesystem_iterator_entry;

typedef struct {
	git_vector entries;
	size_t next_idx;

	size_t path_len;
	int is_ignored;
} filesystem_iterator_frame;

typedef struct {
	git_iterator base;
	char *root;
	size_t root_len;

	unsigned int dirload_flags;

	git_tree *tree;
	git_index *index;
	git_vector index_snapshot;

	git_array_t(filesystem_iterator_frame) frames;
	git_ignores ignores;

	/* info about the current entry */
	git_index_entry entry;
	git_buf current_path;
	int current_is_ignored;
} filesystem_iterator;


GIT_INLINE(filesystem_iterator_frame *) filesystem_iterator_parent_frame(
	filesystem_iterator *iter)
{
	return iter->frames.size > 1 ?
		&iter->frames.ptr[iter->frames.size-2] : NULL;
}

GIT_INLINE(filesystem_iterator_frame *) filesystem_iterator_current_frame(
	filesystem_iterator *iter)
{
	return iter->frames.size ? &iter->frames.ptr[iter->frames.size-1] : NULL;
}

GIT_INLINE(filesystem_iterator_entry *) filesystem_iterator_current_entry(
	filesystem_iterator_frame *frame)
{
	return frame->next_idx == 0 ?
		NULL : frame->entries.contents[frame->next_idx-1];
}

static int filesystem_iterator_entry_cmp(const void *_a, const void *_b)
{
	const filesystem_iterator_entry *a = (const filesystem_iterator_entry *)_a;
	const filesystem_iterator_entry *b = (const filesystem_iterator_entry *)_b;

	return git__strcmp(a->path, b->path);
}

static int filesystem_iterator_entry_cmp_icase(const void *_a, const void *_b)
{
	const filesystem_iterator_entry *a = (const filesystem_iterator_entry *)_a;
	const filesystem_iterator_entry *b = (const filesystem_iterator_entry *)_b;

	return git__strcasecmp(a->path, b->path);
}

#define FILESYSTEM_MAX_DEPTH 100

/**
 * Figure out if an entry is a submodule.
 *
 * We consider it a submodule if the path is listed as a submodule in
 * either the tree or the index.
 */
static int is_submodule(
	bool *out, filesystem_iterator *iter, const char *path, size_t path_len)
{
	bool is_submodule = false;
	int error;

	*out = false;

	/* first see if this path is a submodule in HEAD */
	if (iter->tree) {
		git_tree_entry *entry;
		
		error = git_tree_entry_bypath(&entry, iter->tree, path);

		if (error < 0 && error != GIT_ENOTFOUND)
			return error;

		if (!error) {
			is_submodule = (entry->attr == GIT_FILEMODE_COMMIT);
			git_tree_entry_free(entry);
		}
	}
	
	if (!is_submodule && iter->index) {
		size_t pos;
		
		error = git_index_snapshot_find(&pos,
			&iter->index_snapshot, iter->base.entry_srch, path, path_len, 0);

		if (error < 0 && error != GIT_ENOTFOUND)
			return error;
		
		if (!error) {
			git_index_entry *e = git_vector_get(&iter->index_snapshot, pos);
			is_submodule = (e->mode == GIT_FILEMODE_COMMIT);
		}
	}

	*out = is_submodule;
	return 0;
}

GIT_INLINE(git_dir_flag) filesystem_iterator_dir_flag(git_index_entry *entry)
{
#if defined(GIT_WIN32) && !defined(__MINGW32__)
	return (entry && entry->mode) ?
		(S_ISDIR(entry->mode) ? GIT_DIR_FLAG_TRUE : GIT_DIR_FLAG_FALSE) :
		GIT_DIR_FLAG_UNKNOWN;
#else
	GIT_UNUSED(entry);
	return GIT_DIR_FLAG_UNKNOWN;
#endif
}

static void filesystem_iterator_frame_push_ignores(
	filesystem_iterator *iter,
	filesystem_iterator_entry *frame_entry,
	filesystem_iterator_frame *new_frame)
{
	filesystem_iterator_frame *previous_frame;
	git_dir_flag dir_flag;
	const char *path = frame_entry ? frame_entry->path : "";

	if (!iterator__honor_ignores(&iter->base))
		return;

	/* TODO: nope.  but why do we need a dir_flag here at all?  this is always
	 * a directory, no?
	 */
	dir_flag = filesystem_iterator_dir_flag(frame_entry);

	if (git_ignore__lookup(&new_frame->is_ignored,
			&iter->ignores, path, dir_flag) < 0) {
		giterr_clear();
		new_frame->is_ignored = GIT_IGNORE_NOTFOUND;
	}

	/* if this is not the top level directory... */
	if (frame_entry) {
		const char *relative_path;

		previous_frame = filesystem_iterator_parent_frame(iter);

		/* push new ignores for files in this directory */
		relative_path = frame_entry->path + previous_frame->path_len;

		/* inherit ignored from parent if no rule specified */
		if (new_frame->is_ignored <= GIT_IGNORE_NOTFOUND)
			new_frame->is_ignored = previous_frame->is_ignored;

		git_ignore__push_dir(&iter->ignores, relative_path);
	}
}

static void filesystem_iterator_frame_pop_ignores(
	filesystem_iterator *iter)
{
	if (iterator__honor_ignores(&iter->base))
		git_ignore__pop_dir(&iter->ignores);
}

GIT_INLINE(bool) filesystem_iterator_examine_path(
	bool *is_dir_out,
	iterator_pathlist_search_t *match_out,
	filesystem_iterator *iter,
	filesystem_iterator_entry *frame_entry,
	const char *path,
	size_t path_len)
{
	bool is_dir = 0;
	iterator_pathlist_search_t match = ITERATOR_PATHLIST_FULL;

	*is_dir_out = false;
	*match_out = ITERATOR_PATHLIST_NONE;

	if (iter->base.start_len) {
		int cmp = iter->base.strncomp(path, iter->base.start, path_len);

		/* we haven't stat'ed `path` yet, so we don't yet know if it's a
		 * directory or not.  special case if the current path may be a
		 * directory that matches the start prefix.
		 */
		if (cmp == 0) {
			if (iter->base.start[path_len] == '/')
				is_dir = true;

			else if (iter->base.start[path_len] != '\0')
				cmp = -1;
		}

		if (cmp < 0)
			return false;
	}

	if (iter->base.end_len) {
		int cmp = iter->base.strncomp(path, iter->base.end, iter->base.end_len);

		if (cmp > 0)
			return false;
	}

	/* if we have a pathlist that we're limiting to, examine this path now
	 * to avoid a `stat` if we're not interested in the path.
	 */
	if (iter->base.pathlist.length) {
		/* if our parent was explicitly included, so too are we */
		if (frame_entry && (frame_entry->match == ITERATOR_PATHLIST_IS_DIR ||
			frame_entry->match == ITERATOR_PATHLIST_IS_FILE))
			match = ITERATOR_PATHLIST_FULL;
		else
			match = iterator_pathlist_search(&iter->base, path, path_len);

		if (match == ITERATOR_PATHLIST_NOT_FOUND)
			return false;

		/* Ensure that the pathlist entry lines up with what we expected */
		if (match == ITERATOR_PATHLIST_IS_DIR ||
			match == ITERATOR_PATHLIST_IS_PARENT)
			is_dir = true;
	}

	*is_dir_out = is_dir;
	*match_out = match;
	return true;
}

GIT_INLINE(bool) filesystem_iterator_is_dot_git(
	filesystem_iterator *iter, const char *path, size_t path_len)
{
	size_t len;

	if (!iterator__ignore_dot_git(&iter->base))
		return false;

	if ((len = path_len) < 4)
		return false;

	if (path[len - 1] == '/')
		len--;

	if (git__tolower(path[len - 1]) != 't' ||
		git__tolower(path[len - 2]) != 'i' ||
		git__tolower(path[len - 3]) != 'g' ||
		git__tolower(path[len - 4]) != '.')
		return false;

	return (len == 4 || path[len - 5] == '/');
}

static filesystem_iterator_entry *filesystem_iterator_entry_init(
	const char *path,
	size_t path_len,
	struct stat *statbuf,
	iterator_pathlist_search_t pathlist_match)
{
	filesystem_iterator_entry *entry;
	size_t entry_size;

	/* Make sure to append two bytes, one for the path's null
	 * termination, one for a possible trailing '/' for folders.
	 */
	GITERR_CHECK_ALLOC_ADD3(&entry_size,
		sizeof(filesystem_iterator_entry), path_len, 2);

	entry = git__malloc(entry_size);
	entry->path_len = path_len;
	entry->match = pathlist_match;
	memcpy(entry->path, path, path_len);
	memcpy(&entry->st, statbuf, sizeof(struct stat));

	/* Suffix directory paths with a '/' */
	if (S_ISDIR(entry->st.st_mode))
		entry->path[entry->path_len++] = '/';

	entry->path[entry->path_len] = '\0';

	return entry;
}

static int filesystem_iterator_frame_push(
	filesystem_iterator *iter,
	filesystem_iterator_entry *frame_entry)
{
	filesystem_iterator_frame *new_frame = NULL;
	git_path_diriter diriter = GIT_PATH_DIRITER_INIT;
	git_buf root = GIT_BUF_INIT;
	const char *path;
	filesystem_iterator_entry *entry;
	struct stat statbuf;
	size_t path_len;
	int error;

	if (iter->frames.size == FILESYSTEM_MAX_DEPTH) {
		giterr_set(GITERR_REPOSITORY,
			"directory nesting too deep (%d)", iter->frames.size);
		return -1;
	}

	new_frame = git_array_alloc(iter->frames);
	GITERR_CHECK_ALLOC(new_frame);

	memset(new_frame, 0, sizeof(filesystem_iterator_frame));

	if (frame_entry)
		git_buf_joinpath(&root, iter->root, frame_entry->path);
	else
		git_buf_puts(&root, iter->root);

	if (git_buf_oom(&root)) {
		error = -1;
		goto done;
	}

	new_frame->path_len = frame_entry ? frame_entry->path_len : 0;

	/* Any error here is equivalent to the dir not existing, skip over it */
	if ((error = git_path_diriter_init(
			&diriter, root.ptr, iter->dirload_flags)) < 0) {
		error = GIT_ENOTFOUND;
		goto done;
	}

	if ((error = git_vector_init(&new_frame->entries, 64,
			iterator__ignore_case(&iter->base) ?
			filesystem_iterator_entry_cmp_icase :
			filesystem_iterator_entry_cmp)) < 0)
		goto done;

	/* check if this directory is ignored */
	filesystem_iterator_frame_push_ignores(iter, frame_entry, new_frame);

	while ((error = git_path_diriter_next(&diriter)) == 0) {
		iterator_pathlist_search_t pathlist_match = ITERATOR_PATHLIST_FULL;
		bool dir_expected = false;

		if ((error = git_path_diriter_fullpath(&path, &path_len, &diriter)) < 0)
			goto done;

		assert(path_len > iter->root_len);

		/* remove the prefix if requested */
		path += iter->root_len;
		path_len -= iter->root_len;

		/* examine start / end and the pathlist to see if this path is in it.
		 * note that since we haven't yet stat'ed the path, we cannot know
		 * whether it's a directory yet or not, so this can give us an
		 * expected type (S_IFDIR or S_IFREG) that we should examine)
		 */
		if (!filesystem_iterator_examine_path(&dir_expected, &pathlist_match,
			iter, frame_entry, path, path_len))
			continue;

		/* TODO: don't need to stat if assume unchanged for this path */

		if ((error = git_path_diriter_stat(&statbuf, &diriter)) < 0) {
			/* file was removed between readdir and lstat */
			if (error == GIT_ENOTFOUND)
				continue;

			/* treat the file as unreadable */
			memset(&statbuf, 0, sizeof(statbuf));
			statbuf.st_mode = GIT_FILEMODE_UNREADABLE;
			
			error = 0;
		}

		iter->base.stat_calls++;

		/* Ignore wacky things in the filesystem */
		if (!S_ISDIR(statbuf.st_mode) &&
			!S_ISREG(statbuf.st_mode) &&
			!S_ISLNK(statbuf.st_mode) &&
			statbuf.st_mode != GIT_FILEMODE_UNREADABLE)
			continue;

		if (filesystem_iterator_is_dot_git(iter, path, path_len))
			continue;

		/* convert submodules to GITLINK and remove trailing slashes */
		if (S_ISDIR(statbuf.st_mode)) {
			bool submodule = false;

			if ((error = is_submodule(&submodule, iter, path, path_len)) < 0)
				goto done;

			if (submodule)
				statbuf.st_mode = GIT_FILEMODE_COMMIT;
		}

		/* Ensure that the pathlist entry lines up with what we expected */
		if (dir_expected && !S_ISDIR(statbuf.st_mode))
			continue;

		entry = filesystem_iterator_entry_init(
			path, path_len, &statbuf, pathlist_match);
		GITERR_CHECK_ALLOC(entry);
		
		git_vector_insert(&new_frame->entries, entry);
	}
	
	if (error == GIT_ITEROVER)
		error = 0;

	/* sort now that directory suffix is added */
	git_vector_sort(&new_frame->entries);

done:
	if (error < 0)
		git_array_pop(iter->frames);

	git_buf_free(&root);
	git_path_diriter_free(&diriter);
	return error;
}

GIT_INLINE(void) filesystem_iterator_frame_pop(filesystem_iterator *iter)
{
	filesystem_iterator_frame *frame;

	assert(iter->frames.size);

	frame = git_array_pop(iter->frames);
	filesystem_iterator_frame_pop_ignores(iter);
	
	git_vector_free_deep(&frame->entries);
}

static void filesystem_iterator_set_current(
	filesystem_iterator *iter,
	filesystem_iterator_entry *entry)
{
	iter->entry.ctime.seconds = entry->st.st_ctimespec.tv_sec;
	iter->entry.ctime.nanoseconds = entry->st.st_ctimespec.tv_nsec;

	iter->entry.mtime.seconds = entry->st.st_mtimespec.tv_sec;
	iter->entry.mtime.nanoseconds = entry->st.st_mtimespec.tv_nsec;

	iter->entry.dev = entry->st.st_dev;
	iter->entry.ino = entry->st.st_ino;
	iter->entry.mode = git_futils_canonical_mode(entry->st.st_mode);
	iter->entry.uid = entry->st.st_uid;
	iter->entry.gid = entry->st.st_gid;
	iter->entry.file_size = entry->st.st_size;

	iter->entry.path = entry->path;

	iter->current_is_ignored = GIT_IGNORE_UNCHECKED;
}

static int filesystem_iterator_current(
	const git_index_entry **out, git_iterator *i)
{
	filesystem_iterator *iter = (filesystem_iterator *)i;

	if (!iterator__has_been_accessed(i))
		return iter->base.cb->advance(out, i);

	if (!iter->frames.size) {
		*out = NULL;
		return GIT_ITEROVER;
	}

	*out = &iter->entry;
	return 0;
}

static int filesystem_iterator_advance(
	const git_index_entry **out, git_iterator *i)
{
	filesystem_iterator *iter = (filesystem_iterator *)i;
	int error = 0;

	iter->base.flags |= GIT_ITERATOR_FIRST_ACCESS;
	
	/* examine filesystem entries until we find the next one to return */
	while (true) {
		filesystem_iterator_frame *frame;
		filesystem_iterator_entry *entry;
		
		if ((frame = filesystem_iterator_current_frame(iter)) == NULL) {
			error = GIT_ITEROVER;
			break;
		}
		
		/* no more entries in this frame.  pop the frame out */
		if (frame->next_idx == frame->entries.length) {
			filesystem_iterator_frame_pop(iter);
			continue;
		}

		/* we have more entries in the current frame, that's our next entry */
		entry = frame->entries.contents[frame->next_idx];
		frame->next_idx++;

		if (S_ISDIR(entry->st.st_mode)) {
			if (iterator__do_autoexpand(iter)) {
				error = filesystem_iterator_frame_push(iter, entry);

				/* may get GIT_ENOTFOUND due to races or permission problems
				 * that we want to quietly swallow
				 */
				if (error == GIT_ENOTFOUND)
					continue;
				else if (error < 0)
					break;
			}
			
			if (!iterator__include_trees(iter))
				continue;
		}

		filesystem_iterator_set_current(iter, entry);
		break;
	}

	if (out)
		*out = (error == 0) ? &iter->entry : NULL;

	return error;
}

static int filesystem_iterator_advance_into(
	const git_index_entry **out, git_iterator *i)
{
	filesystem_iterator *iter = (filesystem_iterator *)i;
	filesystem_iterator_frame *frame;
	filesystem_iterator_entry *prev_entry;
	int error;

	if (out)
		*out = NULL;

	if ((frame = filesystem_iterator_current_frame(iter)) == NULL)
		return GIT_ITEROVER;
	
	/* get the last seen entry */
	prev_entry = filesystem_iterator_current_entry(frame);
	
	/* it's legal to call advance_into when auto-expand is on.  in this case,
	 * we will have pushed a new (empty) frame on to the stack for this
	 * new directory.  since it's empty, its current_entry should be null.
	 */
	assert(iterator__do_autoexpand(i) ^ (prev_entry != NULL));
	
	if (prev_entry) {
		if (prev_entry->st.st_mode != GIT_FILEMODE_COMMIT &&
			!S_ISDIR(prev_entry->st.st_mode))
			return 0;

		if ((error = filesystem_iterator_frame_push(iter, prev_entry)) < 0)
			return error;
	}
	
	/* we've advanced into the directory in question, let advance
	 * find the first entry
	 */
	return filesystem_iterator_advance(out, i);
}

int git_iterator_current_workdir_path(git_buf **out, git_iterator *i)
{
	filesystem_iterator *iter = (filesystem_iterator *)i;
	const git_index_entry *entry;

	if (i->type != GIT_ITERATOR_TYPE_FS &&
		i->type != GIT_ITERATOR_TYPE_WORKDIR) {
		*out = NULL;
		return 0;
	}

	git_buf_truncate(&iter->current_path, iter->root_len);

	if (git_iterator_current(&entry, i) < 0 ||
		git_buf_puts(&iter->current_path, entry->path) < 0)
		return -1;
		
	*out = &iter->current_path;
	return 0;
}

GIT_INLINE(git_dir_flag) entry_dir_flag(git_index_entry *entry)
{
#if defined(GIT_WIN32) && !defined(__MINGW32__)
	return (entry && entry->mode) ?
		(S_ISDIR(entry->mode) ? GIT_DIR_FLAG_TRUE : GIT_DIR_FLAG_FALSE) :
		GIT_DIR_FLAG_UNKNOWN;
#else
	GIT_UNUSED(entry);
	return GIT_DIR_FLAG_UNKNOWN;
#endif
}

static void filesystem_iterator_update_ignored(filesystem_iterator *iter)
{
	filesystem_iterator_frame *frame;
	git_dir_flag dir_flag = entry_dir_flag(&iter->entry);

	if (git_ignore__lookup(&iter->current_is_ignored,
			&iter->ignores, iter->entry.path, dir_flag) < 0) {
		giterr_clear();
		iter->current_is_ignored = GIT_IGNORE_NOTFOUND;
	}

	/* use ignore from containing frame stack */
	if (iter->current_is_ignored <= GIT_IGNORE_NOTFOUND) {
		frame = filesystem_iterator_current_frame(iter);
		iter->current_is_ignored = frame->is_ignored;
	}
}

GIT_INLINE(bool) filesystem_iterator_current_is_ignored(
	filesystem_iterator *iter)
{
	if (iter->current_is_ignored == GIT_IGNORE_UNCHECKED)
		filesystem_iterator_update_ignored(iter);
	
	return (iter->current_is_ignored == GIT_IGNORE_TRUE);
}

bool git_iterator_current_is_ignored(git_iterator *i)
{
	if (i->type != GIT_ITERATOR_TYPE_WORKDIR)
		return false;

	return filesystem_iterator_current_is_ignored((filesystem_iterator *)i);
}

bool git_iterator_current_tree_is_ignored(git_iterator *i)
{
	filesystem_iterator *iter = (filesystem_iterator *)i;
	filesystem_iterator_frame *frame;
	
	if (i->type != GIT_ITERATOR_TYPE_WORKDIR)
		return false;

	frame = filesystem_iterator_current_frame(iter);
	return (frame->is_ignored == GIT_IGNORE_TRUE);
}

static int filesystem_iterator_advance_over(
	const git_index_entry **out,
	git_iterator_status_t *status,
	git_iterator *i)
{
	filesystem_iterator *iter = (filesystem_iterator *)i;
	const git_index_entry *entry;
	char *base = NULL;
	int error = 0;

	*out = NULL;
	*status = GIT_ITERATOR_STATUS_NORMAL;
	
	if ((error = git_iterator_current(&entry, i)) < 0)
		return error;
	
	if (!S_ISDIR(entry->mode)) {
		if (filesystem_iterator_current_is_ignored(iter))
			*status = GIT_ITERATOR_STATUS_IGNORED;

		return filesystem_iterator_advance(out, i);
	}
	
	*status = GIT_ITERATOR_STATUS_EMPTY;

	/* TODO: use a git_buf in the iterator to avoid excessive allocations */
	base = git__strdup(entry->path);
	GITERR_CHECK_ALLOC(base);
	
	/* scan inside directory looking for a non-ignored item */
	while (entry && !iter->base.prefixcomp(entry->path, base)) {
		if (filesystem_iterator_current_is_ignored(iter)) {
			/* if we found an explicitly ignored item, then update from
			 * EMPTY to IGNORED
			 */
			*status = GIT_ITERATOR_STATUS_IGNORED;
		} else if (S_ISDIR(entry->mode)) {
			error = filesystem_iterator_advance_into(&entry, i);
			
			if (!error)
				continue;
			
			if (error == GIT_ENOTFOUND) {
				/* we entered this directory only hoping to find child
				 * matches to our pathlist (eg, this is `foo` and we had a
				 * pathlist entry for `foo/bar`).  it should not be ignored,
				 * it should be excluded.
				 */
// TODO TODO TODO
//				if (iter->current_pathlist_match == ITERATOR_PATHLIST_MATCH_CHILD)..
//					*status = GIT_ITERATOR_STATUS_FILTERED;

				/* mark empty dirs ignored */
//				else
					iter->current_is_ignored = GIT_IGNORE_TRUE;

				error = 0;
			} else {
				 /* real error, stop here */
				break;
			}
		} else {
			/* we found a non-ignored item, treat parent as untracked */
			*status = GIT_ITERATOR_STATUS_NORMAL;
			break;
		}
		
		if ((error = git_iterator_advance(&entry, i)) < 0)
			break;
	}
	
	/* wrap up scan back to base directory */
	while (entry && !iter->base.prefixcomp(entry->path, base)) {
		if ((error = git_iterator_advance(&entry, i)) < 0)
			break;
	}

	if (!error)
		*out = entry;

	git__free(base);
	
	return error;
}

static void filesystem_iterator_clear(filesystem_iterator *iter)
{
	while (iter->frames.size)
		filesystem_iterator_frame_pop(iter);

	git_array_clear(iter->frames);
	git_ignore__free(&iter->ignores);
	
	iterator_clear(&iter->base);
}

static int filesystem_iterator_init(filesystem_iterator *iter)
{
	int error;
	
	if (iterator__honor_ignores(&iter->base) &&
		(error = git_ignore__for_path(iter->base.repo,
			".gitignore", &iter->ignores)) < 0)
		return error;

	if ((error = filesystem_iterator_frame_push(iter, NULL)) < 0)
		return error;

	iter->base.flags &= ~GIT_ITERATOR_FIRST_ACCESS;
	
	return 0;
}

static int filesystem_iterator_reset(git_iterator *i)
{
	filesystem_iterator *iter = (filesystem_iterator *)i;
	
	filesystem_iterator_clear(iter);
	return filesystem_iterator_init(iter);
}

static int filesystem_iterator_reset_range(
	git_iterator *i, const char *start, const char *end)
{
	if (iterator_range_reset(i, start, end) < 0)
		return -1;
	
	return filesystem_iterator_reset(i);
}

static int filesystem_iterator_at_end(git_iterator *i)
{
	filesystem_iterator *iter = (filesystem_iterator *)i;

	return (iter->frames.size == 0);
}

static void filesystem_iterator_free(git_iterator *i)
{
	filesystem_iterator *iter = (filesystem_iterator *)i;
	filesystem_iterator_clear(iter);
}

int git_iterator_for_filesystem_ext(
	git_iterator **out,
	git_repository *repo,
	const char *root,
	git_index *index,
	git_tree *tree,
	git_iterator_type_t type,
	git_iterator_options *options)
{
	filesystem_iterator *iter;
	size_t root_len;
	int error;

	static git_iterator_callbacks callbacks = {
		filesystem_iterator_current,
		filesystem_iterator_advance,
		filesystem_iterator_advance_into,
		filesystem_iterator_advance_over,
		filesystem_iterator_reset,
		filesystem_iterator_reset_range,
		filesystem_iterator_at_end,
		filesystem_iterator_free
	};
	
	*out = NULL;
	
	if (root == NULL)
		return git_iterator_for_nothing(out, options);

	iter = git__calloc(1, sizeof(filesystem_iterator));
	GITERR_CHECK_ALLOC(iter);

	root_len = strlen(root);

	iter->root = git__malloc(root_len+2);
	GITERR_CHECK_ALLOC(iter->root);

	memcpy(iter->root, root, root_len);

	if (root_len == 0 || root[root_len-1] != '/') {
		iter->root[root_len] = '/';
		root_len++;
	}
	iter->root[root_len] = '\0';
	iter->root_len = root_len;

	if ((error = git_buf_puts(&iter->current_path, iter->root)) < 0)
		goto on_error;

	iter->base.type = type;
	iter->base.cb = &callbacks;


	if ((error = iterator_init_common(&iter->base, repo, options)) < 0)
		goto on_error;

	if (tree && (error = git_tree_dup(&iter->tree, tree)) < 0)
		goto on_error;
	
	if ((iter->index = index) != NULL &&
		(error = git_index_snapshot_new(&iter->index_snapshot, index)) < 0)
		goto on_error;
	
	iter->dirload_flags =
		(iterator__ignore_case(&iter->base) ? GIT_PATH_DIR_IGNORE_CASE : 0) |
		(iterator__flag(&iter->base, PRECOMPOSE_UNICODE) ?
			 GIT_PATH_DIR_PRECOMPOSE_UNICODE : 0);

	if ((error = filesystem_iterator_init(iter)) < 0)
		goto on_error;

	*out = &iter->base;
	return 0;
	
on_error:
	git__free(iter->root);
	git_buf_free(&iter->current_path);
	git_iterator_free(&iter->base);
	return error;
}

int git_iterator_for_filesystem(
	git_iterator **out,
	const char *root,
	git_iterator_options *options)
{
	return git_iterator_for_filesystem_ext(out,
		NULL, root, NULL, NULL, GIT_ITERATOR_TYPE_FS, options);
}

int git_iterator_for_workdir_ext(
	git_iterator **out,
	git_repository *repo,
	const char *repo_workdir,
	git_index *index,
	git_tree *tree,
	git_iterator_options *given_opts)
{
	git_iterator_options options = GIT_ITERATOR_OPTIONS_INIT;
	int error;

	if (!repo_workdir) {
		if (git_repository__ensure_not_bare(repo, "scan working directory") < 0)
			return GIT_EBAREREPO;

		repo_workdir = git_repository_workdir(repo);
	}

	/* upgrade to a workdir iterator, adding necessary internal flags */
	memcpy(&options, given_opts, sizeof(git_iterator_options));
	options.flags |= GIT_ITERATOR_HONOR_IGNORES |
		GIT_ITERATOR_IGNORE_DOT_GIT;

	error = git_iterator_for_filesystem_ext(out,
		repo, repo_workdir, index, tree, GIT_ITERATOR_TYPE_WORKDIR, &options);

	return error;
}


/* Index iterator */


typedef struct {
	git_iterator base;
	git_iterator_callbacks cb;
	git_index *index;
	git_vector entries;
	git_vector_cmp entry_srch;
	size_t current;
	/* when limiting with a pathlist, this is the current index into it */
	size_t pathlist_idx;
	/* when not in autoexpand mode, use these to represent "tree" state */
	git_buf partial;
	size_t partial_pos;
	char restore_terminator;
	git_index_entry tree_entry;
} index_iterator;

static const git_index_entry *index_iterator__index_entry(index_iterator *ii)
{
	const git_index_entry *ie = git_vector_get(&ii->entries, ii->current);

	if (ie != NULL && iterator__past_end(ii, ie->path)) {
		ii->current = git_vector_length(&ii->entries);
		ie = NULL;
	}

	return ie;
}

static const git_index_entry *index_iterator__advance_over_unwanted(
	index_iterator *ii)
{
	const git_index_entry *ie = index_iterator__index_entry(ii);
	bool match;

	while (ie) {
		if (!iterator__include_conflicts(ii) &&
				git_index_entry_is_conflict(ie)) {
			ii->current++;
			ie = index_iterator__index_entry(ii);
			continue;
		}

		/* if we have a pathlist, this entry's path must be in it to be
		 * returned.  walk the pathlist in unison with the index to
		 * compare paths.
		 */
		if (ii->base.pathlist.length) {
			match = iterator_pathlist_walk__contains(&ii->base, ie->path);

			if (!match) {
				ii->current++;
				ie = index_iterator__index_entry(ii);
				continue;
			}
		}

		break;
	}

	return ie;
}

static void index_iterator__next_prefix_tree(index_iterator *ii)
{
	const char *slash;

	if (!iterator__include_trees(ii))
		return;

	slash = strchr(&ii->partial.ptr[ii->partial_pos], '/');

	if (slash != NULL) {
		ii->partial_pos = (slash - ii->partial.ptr) + 1;
		ii->restore_terminator = ii->partial.ptr[ii->partial_pos];
		ii->partial.ptr[ii->partial_pos] = '\0';
	} else {
		ii->partial_pos = ii->partial.size;
	}

	if (index_iterator__index_entry(ii) == NULL)
		ii->partial_pos = ii->partial.size;
}

static int index_iterator__first_prefix_tree(index_iterator *ii)
{
	const git_index_entry *ie = index_iterator__advance_over_unwanted(ii);
	const char *scan, *prior, *slash;

	if (!ie || !iterator__include_trees(ii))
		return 0;

	/* find longest common prefix with prior index entry */
	for (scan = slash = ie->path, prior = ii->partial.ptr;
		 *scan && *scan == *prior; ++scan, ++prior)
		if (*scan == '/')
			slash = scan;

	if (git_buf_sets(&ii->partial, ie->path) < 0)
		return -1;

	ii->partial_pos = (slash - ie->path) + 1;
	index_iterator__next_prefix_tree(ii);

	return 0;
}

#define index_iterator__at_tree(I) \
	(iterator__include_trees(I) && (I)->partial_pos < (I)->partial.size)

static int index_iterator__current(
	const git_index_entry **entry, git_iterator *self)
{
	index_iterator *ii = (index_iterator *)self;
	const git_index_entry *ie = git_vector_get(&ii->entries, ii->current);

	if (ie != NULL && index_iterator__at_tree(ii)) {
		ii->tree_entry.path = ii->partial.ptr;
		ie = &ii->tree_entry;
	}

	if (entry)
		*entry = ie;

	ii->base.flags |= GIT_ITERATOR_FIRST_ACCESS;

	return (ie != NULL) ? 0 : GIT_ITEROVER;
}

static int index_iterator__at_end(git_iterator *self)
{
	index_iterator *ii = (index_iterator *)self;
	return (ii->current >= git_vector_length(&ii->entries));
}

static int index_iterator__advance(
	const git_index_entry **entry, git_iterator *self)
{
	index_iterator *ii = (index_iterator *)self;
	size_t entrycount = git_vector_length(&ii->entries);
	const git_index_entry *ie;

	if (!iterator__has_been_accessed(ii))
		return index_iterator__current(entry, self);

	if (index_iterator__at_tree(ii)) {
		if (iterator__do_autoexpand(ii)) {
			ii->partial.ptr[ii->partial_pos] = ii->restore_terminator;
			index_iterator__next_prefix_tree(ii);
		} else {
			/* advance to sibling tree (i.e. find entry with new prefix) */
			while (ii->current < entrycount) {
				ii->current++;

				if (!(ie = git_vector_get(&ii->entries, ii->current)) ||
					ii->base.prefixcomp(ie->path, ii->partial.ptr) != 0)
					break;
			}

			if (index_iterator__first_prefix_tree(ii) < 0)
				return -1;
		}
	} else {
		if (ii->current < entrycount)
			ii->current++;

		if (index_iterator__first_prefix_tree(ii) < 0)
			return -1;
	}

	return index_iterator__current(entry, self);
}

static int index_iterator__advance_into(
	const git_index_entry **entry, git_iterator *self)
{
	index_iterator *ii = (index_iterator *)self;
	const git_index_entry *ie = git_vector_get(&ii->entries, ii->current);

	if (ie != NULL && index_iterator__at_tree(ii)) {
		if (ii->restore_terminator)
			ii->partial.ptr[ii->partial_pos] = ii->restore_terminator;
		index_iterator__next_prefix_tree(ii);
	}

	return index_iterator__current(entry, self);
}

static int index_iterator__reset(git_iterator *self)
{
	index_iterator *ii = (index_iterator *)self;
	const git_index_entry *ie;

	ii->current = 0;
	ii->base.flags &= ~GIT_ITERATOR_FIRST_ACCESS;

	iterator_pathlist_walk__reset(self);

	/* if we're given a start prefix, find it; if we're given a pathlist, find
	 * the first of those.  start at the later of the two.
	 */
	if (ii->base.start)
		git_index_snapshot_find(
			&ii->current, &ii->entries, ii->entry_srch, ii->base.start, 0, 0);

	if ((ie = index_iterator__advance_over_unwanted(ii)) == NULL)
		return 0;

	if (git_buf_sets(&ii->partial, ie->path) < 0)
		return -1;

	ii->partial_pos = 0;

	if (ii->base.start) {
		size_t startlen = strlen(ii->base.start);

		ii->partial_pos = (startlen > ii->partial.size) ?
			ii->partial.size : startlen;
	}

	index_iterator__next_prefix_tree(ii);

	return 0;
}

static int index_iterator__reset_range(
	git_iterator *self, const char *start, const char *end)
{
	if (iterator__reset_range(self, start, end) < 0)
		return -1;

	return index_iterator__reset(self);
}

static void index_iterator__free(git_iterator *self)
{
	index_iterator *ii = (index_iterator *)self;
	git_index_snapshot_release(&ii->entries, ii->index);
	ii->index = NULL;
	git_buf_free(&ii->partial);
}

int git_iterator_for_index(
	git_iterator **iter,
	git_repository *repo,
	git_index  *index,
	git_iterator_options *options)
{
	int error = 0;
	index_iterator *ii = git__calloc(1, sizeof(index_iterator));
	GITERR_CHECK_ALLOC(ii);

	if ((error = git_index_snapshot_new(&ii->entries, index)) < 0) {
		git__free(ii);
		return error;
	}
	ii->index = index;

	ITERATOR_BASE_INIT(ii, index, INDEX, repo);

	if ((error = iterator__update_ignore_case((git_iterator *)ii, options ? options->flags : 0)) < 0) {
		git_iterator_free((git_iterator *)ii);
		return error;
	}

	ii->entry_srch = iterator__ignore_case(ii) ?
		git_index_entry_isrch : git_index_entry_srch;

	git_vector_set_cmp(&ii->entries, iterator__ignore_case(ii) ?
		git_index_entry_icmp : git_index_entry_cmp);
	git_vector_sort(&ii->entries);

	git_buf_init(&ii->partial, 0);
	ii->tree_entry.mode = GIT_FILEMODE_TREE;

	index_iterator__reset((git_iterator *)ii);

	*iter = (git_iterator *)ii;
	return 0;
}


void git_iterator_free(git_iterator *iter)
{
	if (iter == NULL)
		return;

	iter->cb->free(iter);

	git_vector_free(&iter->pathlist);
	git__free(iter->start);
	git__free(iter->end);

	memset(iter, 0, sizeof(*iter));

	git__free(iter);
}

int git_iterator_cmp(git_iterator *iter, const char *path_prefix)
{
	const git_index_entry *entry;

	/* a "done" iterator is after every prefix */
	if (git_iterator_current(&entry, iter) < 0 || entry == NULL)
		return 1;

	/* a NULL prefix is after any valid iterator */
	if (!path_prefix)
		return -1;

	return iter->prefixcomp(entry->path, path_prefix);
}

git_index *git_iterator_index(git_iterator *iter)
{
	if (iter->type == GIT_ITERATOR_TYPE_INDEX)
		return ((index_iterator *)iter)->index;

	if (iter->type == GIT_ITERATOR_TYPE_FS ||
		iter->type == GIT_ITERATOR_TYPE_WORKDIR)
		return ((filesystem_iterator *)iter)->index;

	return NULL;
}

int git_iterator_walk(
	git_iterator **iterators,
	size_t cnt,
	git_iterator_walk_cb cb,
	void *data)
{
	const git_index_entry **iterator_item;	/* next in each iterator */
	const git_index_entry **cur_items;		/* current path in each iter */
	const git_index_entry *first_match;
	size_t i, j;
	int error = 0;

	iterator_item = git__calloc(cnt, sizeof(git_index_entry *));
	cur_items = git__calloc(cnt, sizeof(git_index_entry *));

	GITERR_CHECK_ALLOC(iterator_item);
	GITERR_CHECK_ALLOC(cur_items);

	/* Set up the iterators */
	for (i = 0; i < cnt; i++) {
		error = git_iterator_current(&iterator_item[i], iterators[i]);

		if (error < 0 && error != GIT_ITEROVER)
			goto done;
	}

	while (true) {
		for (i = 0; i < cnt; i++)
			cur_items[i] = NULL;

		first_match = NULL;

		/* Find the next path(s) to consume from each iterator */
		for (i = 0; i < cnt; i++) {
			if (iterator_item[i] == NULL)
				continue;

			if (first_match == NULL) {
				first_match = iterator_item[i];
				cur_items[i] = iterator_item[i];
			} else {
				int path_diff = git_index_entry_cmp(iterator_item[i], first_match);

				if (path_diff < 0) {
					/* Found an index entry that sorts before the one we're
					 * looking at.  Forget that we've seen the other and
					 * look at the other iterators for this path.
					 */
					for (j = 0; j < i; j++)
						cur_items[j] = NULL;

					first_match = iterator_item[i];
					cur_items[i] = iterator_item[i];
				} else if (path_diff == 0) {
					cur_items[i] = iterator_item[i];
				}
			}
		}

		if (first_match == NULL)
			break;

		if ((error = cb(cur_items, data)) != 0)
			goto done;

		/* Advance each iterator that participated */
		for (i = 0; i < cnt; i++) {
			if (cur_items[i] == NULL)
				continue;

			error = git_iterator_advance(&iterator_item[i], iterators[i]);

			if (error < 0 && error != GIT_ITEROVER)
				goto done;
		}
	}

done:
	git__free((git_index_entry **)iterator_item);
	git__free((git_index_entry **)cur_items);

	if (error == GIT_ITEROVER)
		error = 0;

	return error;
}
