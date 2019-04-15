/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file path.c
 *
 * \brief Manipulate strings that contain filesystem paths.
 **/

#include "lib/fs/path.h"
#include "lib/malloc/malloc.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"
#include "lib/log/win32err.h"
#include "lib/container/smartlist.h"
#include "lib/sandbox/sandbox.h"
#include "lib/string/printf.h"
#include "lib/string/util_string.h"
#include "lib/string/compat_string.h"
#include "lib/string/compat_ctype.h"
#include "lib/fs/files.h"
#include "lib/fs/userdb.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef _WIN32
#include <windows.h>
#else /* !(defined(_WIN32)) */
#include <dirent.h>
#include <glob.h>
#endif /* defined(_WIN32) */

#include <errno.h>
#include <string.h>

/** Represents a function that unglobs <b>pattern</b>. Returns a list of paths
 * that match <b>pattern</b>. See comments on process_glob to understand why
 * this is necessary. */
typedef struct smartlist_t *(*unglob_fn)(const char *pattern);

/** Represents a function called when a pattern is first processed.
 *   - <b>pattern</b> - pattern being processed
 *   - <b>start_sep</b> - index of separator before path component being
 *                        processed
 *   - <b>end_sep</b> - index of separator after path component being processed
 *   - <b>result</b> - current results list, items may be added to this list
 * Return false if <b>pattern</b> is to be ignored, true otherwise
 **/
typedef bool (*handle_glob_fn)(const char *pattern, int start_sep, int end_sep,
                               smartlist_t *results);

/** Represents a function called for each path resulting from the expansion of
 * a path component containing a glob.
 *  - <b>file_type</b> - type of path resulting from the glob expansion
 *  - <b>pattern_after</b> - what is after the path component being expanded
 * Return false if path is to be ignored, true otherwise
 **/
typedef bool (*glob_predicate_fn)(file_status_t file_type,
                                  const char *pattern_after);

static struct smartlist_t *
process_glob(const char *pattern, int add_no_glob, unglob_fn unglob,
             handle_glob_fn handle_glob, glob_predicate_fn should_append,
             glob_predicate_fn should_recurse);

/** Removes enclosing quotes from <b>path</b> and unescapes quotes between the
 * enclosing quotes. Backslashes are not unescaped. Return the unquoted
 * <b>path</b> on success or 0 if <b>path</b> is not quoted correctly. */
char *
get_unquoted_path(const char *path)
{
  size_t len = strlen(path);

  if (len == 0) {
    return tor_strdup("");
  }

  int has_start_quote = (path[0] == '\"');
  int has_end_quote = (len > 0 && path[len-1] == '\"');
  if (has_start_quote != has_end_quote || (len == 1 && has_start_quote)) {
    return NULL;
  }

  char *unquoted_path = tor_malloc(len - has_start_quote - has_end_quote + 1);
  char *s = unquoted_path;
  size_t i;
  for (i = has_start_quote; i < len - has_end_quote; i++) {
    if (path[i] == '\"' && (i > 0 && path[i-1] == '\\')) {
      *(s-1) = path[i];
    } else if (path[i] != '\"') {
      *s++ = path[i];
    } else {  /* unescaped quote */
      tor_free(unquoted_path);
      return NULL;
    }
  }
  *s = '\0';
  return unquoted_path;
}

/** Expand any homedir prefix on <b>filename</b>; return a newly allocated
 * string. */
char *
expand_filename(const char *filename)
{
  tor_assert(filename);
#ifdef _WIN32
  /* Might consider using GetFullPathName() as described here:
   * http://etutorials.org/Programming/secure+programming/
   *     Chapter+3.+Input+Validation/3.7+Validating+Filenames+and+Paths/
   */
  return tor_strdup(filename);
#else /* !(defined(_WIN32)) */
  if (*filename == '~') {
    char *home, *result=NULL;
    const char *rest;

    if (filename[1] == '/' || filename[1] == '\0') {
      home = getenv("HOME");
      if (!home) {
        log_warn(LD_CONFIG, "Couldn't find $HOME environment variable while "
                 "expanding \"%s\"; defaulting to \"\".", filename);
        home = tor_strdup("");
      } else {
        home = tor_strdup(home);
      }
      rest = strlen(filename)>=2?(filename+2):"";
    } else {
#ifdef HAVE_PWD_H
      char *username, *slash;
      slash = strchr(filename, '/');
      if (slash)
        username = tor_strndup(filename+1,slash-filename-1);
      else
        username = tor_strdup(filename+1);
      if (!(home = get_user_homedir(username))) {
        log_warn(LD_CONFIG,"Couldn't get homedir for \"%s\"",username);
        tor_free(username);
        return NULL;
      }
      tor_free(username);
      rest = slash ? (slash+1) : "";
#else /* !(defined(HAVE_PWD_H)) */
      log_warn(LD_CONFIG, "Couldn't expand homedir on system without pwd.h");
      return tor_strdup(filename);
#endif /* defined(HAVE_PWD_H) */
    }
    tor_assert(home);
    /* Remove trailing slash. */
    if (strlen(home)>1 && !strcmpend(home,PATH_SEPARATOR)) {
      home[strlen(home)-1] = '\0';
    }
    tor_asprintf(&result,"%s"PATH_SEPARATOR"%s",home,rest);
    tor_free(home);
    return result;
  } else {
    return tor_strdup(filename);
  }
#endif /* defined(_WIN32) */
}

/** Return true iff <b>filename</b> is a relative path. */
int
path_is_relative(const char *filename)
{
  if (filename && filename[0] == '/')
    return 0;
#ifdef _WIN32
  else if (filename && filename[0] == '\\')
    return 0;
  else if (filename && strlen(filename)>3 && TOR_ISALPHA(filename[0]) &&
           filename[1] == ':' && filename[2] == '\\')
    return 0;
#endif /* defined(_WIN32) */
  else
    return 1;
}

/** Clean up <b>name</b> so that we can use it in a call to "stat".  On Unix,
 * we do nothing.  On Windows, we remove a trailing slash, unless the path is
 * the root of a disk. */
void
clean_fname_for_stat(char *name)
{
#ifdef _WIN32
  size_t len = strlen(name);
  if (!len)
    return;
  if (name[len-1]=='\\' || name[len-1]=='/') {
    if (len == 1 || (len==3 && name[1]==':'))
      return;
    name[len-1]='\0';
  }
#else /* !(defined(_WIN32)) */
  (void)name;
#endif /* defined(_WIN32) */
}

/** Modify <b>fname</b> to contain the name of its parent directory.  Doesn't
 * actually examine the filesystem; does a purely syntactic modification.
 *
 * The parent of the root director is considered to be iteself.
 *
 * Path separators are the forward slash (/) everywhere and additionally
 * the backslash (\) on Win32.
 *
 * Cuts off any number of trailing path separators but otherwise ignores
 * them for purposes of finding the parent directory.
 *
 * Returns 0 if a parent directory was successfully found, -1 otherwise (fname
 * did not have any path separators or only had them at the end).
 * */
int
get_parent_directory(char *fname)
{
  char *cp;
  int at_end = 1;
  tor_assert(fname);
#ifdef _WIN32
  /* If we start with, say, c:, then don't consider that the start of the path
   */
  if (fname[0] && fname[1] == ':') {
    fname += 2;
  }
#endif /* defined(_WIN32) */
  /* Now we want to remove all path-separators at the end of the string,
   * and to remove the end of the string starting with the path separator
   * before the last non-path-separator.  In perl, this would be
   *   s#[/]*$##; s#/[^/]*$##;
   * on a unixy platform.
   */
  cp = fname + strlen(fname);
  at_end = 1;
  while (--cp >= fname) {
    int is_sep = (*cp == '/'
#ifdef _WIN32
                  || *cp == '\\'
#endif
                  );
    if (is_sep) {
      if (cp == fname) {
        /* This is the first separator in the file name; don't remove it! */
        cp[1] = '\0';
        return 0;
      }
      *cp = '\0';
      if (! at_end)
        return 0;
    } else {
      at_end = 0;
    }
  }
  return -1;
}

#ifndef _WIN32
/** Return a newly allocated string containing the output of getcwd(). Return
 * NULL on failure. (We can't just use getcwd() into a PATH_MAX buffer, since
 * Hurd hasn't got a PATH_MAX.)
 */
static char *
alloc_getcwd(void)
{
#ifdef HAVE_GET_CURRENT_DIR_NAME
  /* Glibc makes this nice and simple for us. */
  char *cwd = get_current_dir_name();
  char *result = NULL;
  if (cwd) {
    /* We make a copy here, in case tor_malloc() is not malloc(). */
    result = tor_strdup(cwd);
    raw_free(cwd); // alias for free to avoid tripping check-spaces.
  }
  return result;
#else /* !(defined(HAVE_GET_CURRENT_DIR_NAME)) */
  size_t size = 1024;
  char *buf = NULL;
  char *ptr = NULL;

  while (ptr == NULL) {
    buf = tor_realloc(buf, size);
    ptr = getcwd(buf, size);

    if (ptr == NULL && errno != ERANGE) {
      tor_free(buf);
      return NULL;
    }

    size *= 2;
  }
  return buf;
#endif /* defined(HAVE_GET_CURRENT_DIR_NAME) */
}
#endif /* !defined(_WIN32) */

/** Expand possibly relative path <b>fname</b> to an absolute path.
 * Return a newly allocated string, possibly equal to <b>fname</b>. */
char *
make_path_absolute(char *fname)
{
#ifdef _WIN32
  char *absfname_malloced = _fullpath(NULL, fname, 1);

  /* We don't want to assume that tor_free can free a string allocated
   * with malloc.  On failure, return fname (it's better than nothing). */
  char *absfname = tor_strdup(absfname_malloced ? absfname_malloced : fname);
  if (absfname_malloced) raw_free(absfname_malloced);

  return absfname;
#else /* !(defined(_WIN32)) */
  char *absfname = NULL, *path = NULL;

  tor_assert(fname);

  if (fname[0] == '/') {
    absfname = tor_strdup(fname);
  } else {
    path = alloc_getcwd();
    if (path) {
      tor_asprintf(&absfname, "%s/%s", path, fname);
      tor_free(path);
    } else {
      /* LCOV_EXCL_START Can't make getcwd fail. */
      /* If getcwd failed, the best we can do here is keep using the
       * relative path.  (Perhaps / isn't readable by this UID/GID.) */
      log_warn(LD_GENERAL, "Unable to find current working directory: %s",
               strerror(errno));
      absfname = tor_strdup(fname);
      /* LCOV_EXCL_STOP */
    }
  }
  return absfname;
#endif /* defined(_WIN32) */
}

/**** Helper functions of type glob_predicate_fn used for glob processing ****/

/** Wrapper to is_file of type glob_predicate_fn. */
static bool
is_file_pred(file_status_t file_type, const char *pattern_after)
{
  (void)pattern_after;
  return is_file(file_type);
}

/** Wrapper to is_dir of type glob_predicate_fn. */
static bool
is_dir_pred(file_status_t file_type, const char *pattern_after)
{
  (void)pattern_after;
  return is_dir(file_type);
}

#ifdef _WIN32
/** Returns true if the path where <b>file_type</b> was obtained from
 * concatenated with <b>pattern_after</b> is a complete path and points to an
 * existing file or directory. Returns false otherwise. */
static bool
no_pattern_after(file_status_t file_type, const char *pattern_after)
{
  return (is_file(file_type) || is_dir(file_type)) && !*pattern_after;
}

/** Returns true if the path where <b>file_type</b> was obtained from points to
 * an existing directory and <b>pattern_after</b> is not empty. */
static bool
dir_pattern_after(file_status_t file_type, const char *pattern_after)
{
  return is_dir(file_type) && *pattern_after;
}
#endif /* defined(_WIN32) */

/*****************************************************************************/

/** Returns a copy of <b>path</b> cut before <b>sep_index</b>. */
static char *
get_path_until_separator(const char *path, int sep_index)
{
  size_t len = sep_index < 1 ? sep_index + 1 : sep_index;
  return tor_strndup(path, len);
}

/***** Helper functions of type handle_glob_fn used for glob processing ******/

#ifdef _WIN32
/** Returns true if <b>pattern</b> cut before <b>start_sep</b> is the path of
 * an existing directory. Returns false otherwise. */
static bool
handle_glob_win32(const char *pattern, int start_sep, int end_sep,
                  smartlist_t *result)
{
  (void)end_sep;
  (void)result;

  char *path_until_glob = get_path_until_separator(pattern, start_sep);
  file_status_t file_type = file_status(path_until_glob);
  tor_free(path_until_glob);
  return file_type == FN_DIR;
}
#endif /* defined(_WIN32) */

/** Adds <b>pattern</b> cut before <b>start_sep</b> to <b>results</b>. Returns
 * true if <b>pattern</b> contains a glob after <b>end_sep</b>. Returns false
 * otherwise. */
static bool
handle_glob_opened_files(const char *pattern, int start_sep, int end_sep,
                         smartlist_t *result)
{
  char *path_until_glob = get_path_until_separator(pattern, start_sep);
  smartlist_add(result, path_until_glob);
  // if the following fragments have no globs, we're done
  const char *pattern_after = &pattern[end_sep+1];
  return has_glob(pattern_after);
}

/*****************************************************************************/

#ifdef _WIN32
/** Removes the file name and the path separator preceding it from <b>path</b>.
 * If there are no path separators, <b>path</b> becomes an empty string. */
static void
remove_filename(TCHAR *path)
{
  // remove file name and last path separator from tpattern
  // used later to create the full path
  char *lastSep = strrchr(path, *PATH_SEPARATOR);
  char *lastSepUnix = strrchr(path, '/');
  lastSep = lastSep == NULL ? path : lastSep;
  lastSepUnix = lastSepUnix == NULL ? path : lastSepUnix;
  lastSep = lastSep > lastSepUnix ? lastSep : lastSepUnix;
  *lastSep = '\0';
}
#endif /* defined(_WIN32) */

#ifdef _WIN32
/** Copies at most <b>len</b> characters from <b>src</b> to <b>dst</b>.
 * Multibyte characters are converted to wide characters. */
void
copy_path(TCHAR *dst, const char *src, size_t len)
{
#ifdef UNICODE
  mbstowcs(dst, src, len);
#else
  strlcpy(dst, src, len);
#endif
}
#endif /* defined(_WIN32) */

#ifdef _WIN32
/** Returns a list of files present on the folder opened by <b>handle</b> and
 * using <b>findData</b>. If <b>use_fullpath</b> is true, prepend <b>tpath</b>
 * to each result. */
struct smartlist_t *
get_files_in_folder(HANDLE handle, WIN32_FIND_DATA *findData, TCHAR *tpath,
                    const char *path, bool use_fullpath)
{
  char name[MAX_PATH*2+1] = {0};
  smartlist_t *result = smartlist_new();
  while (1) {
#ifdef UNICODE
    wcstombs(name, findData->cFileName, MAX_PATH);
    name[sizeof(name)-1] = '\0';
#else
    strlcpy(name, findData->cFileName, sizeof(name));
#endif /* defined(UNICODE) */
    if (strcmp(name, ".") && strcmp(name, "..")) {
      if (use_fullpath) {
        char *fullpath;
        tor_asprintf(&fullpath, "%s"PATH_SEPARATOR"%s", tpath, name);
        smartlist_add(result, fullpath);
      } else {
        smartlist_add_strdup(result, name);
      }
    }
    if (!FindNextFile(handle, findData)) {
      DWORD err;
      if ((err = GetLastError()) != ERROR_NO_MORE_FILES) {
        char *errstr = format_win32_error(err);
        log_warn(LD_FS, "Error reading directory '%s': %s", path, errstr);
        tor_free(errstr);
      }
      break;
    }
  }
  return result;
}
#endif /* defined(_WIN32) */

#ifdef _WIN32
/** Returns a list of paths that match <b>pattern</b>. Retruns NULL on error.
 * Due to Windows API limitations, globs are only accepted on the last path
 * component. */
static smartlist_t *
unglob_file_name(const char *pattern)
{
  TCHAR tpattern[MAX_PATH] = {0};
  HANDLE handle;
  WIN32_FIND_DATA findData;
  copy_path(tpattern, pattern, MAX_PATH);
  clean_fname_for_stat(tpattern);  // remove trailing backslash
  if (file_status(tpattern) == FN_DIR) {
    // special case: we want to return the directory and not the files inside
    smartlist_t *ret = smartlist_new();
    smartlist_add_strdup(ret, tpattern);
    return ret;
  }
  if (INVALID_HANDLE_VALUE == (handle = FindFirstFile(tpattern, &findData))) {
    return GetLastError() == ERROR_FILE_NOT_FOUND ? smartlist_new() : NULL;
  }
  remove_filename(tpattern);  // used later to create the full path
  smartlist_t *result = get_files_in_folder(handle, &findData, tpattern,
                                            pattern, true);
  FindClose(handle);
  return result;
}
#endif /* defined(_WIN32) */

/** If <b>path</b> represents an existing file, add it to <b>results</b>
 * without the trailing separator. Otherwise do nothing. */
static void
add_to_results(const char *path, smartlist_t *results)
{
  file_status_t file_type = file_status(path);
  char *clean_path = tor_strdup(path);
  clean_fname_for_stat(clean_path);
  if (is_file(file_type) || is_dir(file_type)) {
    smartlist_add(results, clean_path);
  } else {
    tor_free(clean_path);
  }
}

/** Returns a list of paths that match the first <b>len</b> characters of
 * <b>pattern</b> using <b>unglob</b> to expand it. Returns NULL on error. */
static smartlist_t *
unglob_fragment(const char *pattern, size_t len, unglob_fn unglob)
{
  char *glob_path = tor_strndup(pattern, len);
  smartlist_t *unglobbed_paths = unglob(glob_path);
  tor_free(glob_path);
  return unglobbed_paths;
}

/** Auxiliary function used by process_glob. Processes a path component with a
 * glob inside <b>pattern</b>.  See the comments on process_glob for details.
 *
 * The extra arguments mean:
 *  - start_sep - index of path separator before component
 *  - end_sep - index of path separator after component or last char of pattern
 *  - is_sep - 1 if pattern[end_sep] is a path separator, 0 otherwise
 * */
static int
process_glob_aux(const char *pattern, int start_sep, int end_sep, int is_sep,
                 smartlist_t *results, int add_no_glob, unglob_fn unglob,
                 handle_glob_fn handle_glob, glob_predicate_fn should_append,
                 glob_predicate_fn should_recurse)
{
  // decide if we add the current fragment to results and if we expand it
  if (handle_glob && !handle_glob(pattern, start_sep, end_sep, results)) {
    return 0;
  }

  // unglob current fragment
  int is_last = !pattern[end_sep+1];
  size_t glob_size = is_last && !is_sep ? end_sep + 1 : end_sep;
  smartlist_t *unglobbed_paths = unglob_fragment(pattern, glob_size, unglob);
  if (!unglobbed_paths) {
    return -1;
  }

  // for each path for current fragment, add the rest of the pattern and call
  // recursively to get all paths
  int error_found = 0;
  const char *pattern_after = &pattern[end_sep + 1]; // skip separator
  SMARTLIST_FOREACH_BEGIN(unglobbed_paths, char *, current_path) {
    file_status_t file_type = file_status(current_path);
    if (should_recurse && should_recurse(file_type, pattern_after)) {
      char *next_path;
      smartlist_t *glob_next;
      tor_asprintf(&next_path, "%s"PATH_SEPARATOR"%s", current_path,
                   pattern_after);
      glob_next = process_glob(next_path, add_no_glob, unglob, handle_glob,
                               should_append, should_recurse);
      tor_free(next_path);
      if (!glob_next) {
        error_found = 1;
        break;
      }
      smartlist_add_all(results, glob_next);
      smartlist_free(glob_next);
    // ignore non-directories if the pattern ends in path separator
    } else if (!(is_last && is_sep && file_type != FN_DIR)) {
      if (should_append && should_append(file_type, pattern_after)) {
        smartlist_add_strdup(results, current_path);
      }
    }
  } SMARTLIST_FOREACH_END(current_path);
  SMARTLIST_FOREACH(unglobbed_paths, char *, p, tor_free(p));
  smartlist_free(unglobbed_paths);
  return error_found;
}

/** Picks the first component of <b>pattern</b> that has a glob and decides if
 * it is processed further and if it is added to results using
 * <b>handle_glob</b>. If processed further, it is expanded and the expanded
 * paths are either handled recursively, added to results or ignored.
 * <b>should_append</b> and <b>should_recurse</b> to decide the correct action.
 *
 * If <b>pattern</b> has no globs, <b>add_no_glob</b> decides if it is added to
 * results.
 *
 * <b>unglob</b> is used to unglob patterns. This is necessary because this
 * function is called by win32 implementation of tor_glob which then cannot use
 * tor_glob to process globs in paths.
 *
 * This function itself just handles the case when there are no globs and finds
 * the first path component with a glob. The rest of the work is done by
 * auxiliary function process_glob_aux.
 * */
static struct smartlist_t *
process_glob(const char *pattern, int add_no_glob, unglob_fn unglob,
             handle_glob_fn handle_glob, glob_predicate_fn should_append,
             glob_predicate_fn should_recurse)
{
  int i, start_sep = -1, end_sep = -1, glob_found = 0, is_last = 0, is_sep = 0;
  smartlist_t *results = smartlist_new();

  if (!has_glob(pattern)) {
    if (add_no_glob) {
      add_to_results(pattern, results);
    }
    return results;
  }

  // find start and end of first glob fragment
  for (i = 0; pattern[i]; i++) {
    glob_found = glob_found || IS_GLOB_CHAR(pattern, i);
    is_last = !pattern[i+1];
    is_sep = pattern[i] == *PATH_SEPARATOR;
#ifdef _WIN32
    is_sep = is_sep || pattern[i] == '/';
#endif
    if (is_sep || is_last) {
      start_sep = end_sep;
      end_sep = i;
      if (glob_found) {
        break;
      }
    }
  }

  if (process_glob_aux(pattern, start_sep, end_sep, is_sep, results,
                       add_no_glob, unglob, handle_glob, should_append,
                       should_recurse) < 0) {
    SMARTLIST_FOREACH(results, char *, p, tor_free(p));
    smartlist_free(results);
    results = NULL;
  }
  return results;
}

#ifndef _WIN32
/** Same as opendir but calls sandbox_intern_string before */
static DIR *
prot_opendir(const char *name)
{
  return opendir(sandbox_intern_string(name));
}

/** Same as stat but calls sandbox_intern_string before */
static int
prot_stat(const char *pathname, struct stat *buf)
{
  return stat(sandbox_intern_string(pathname), buf);
}

/** Same as lstat but calls sandbox_intern_string before */
static int
prot_lstat(const char *pathname, struct stat *buf)
{
  return lstat(sandbox_intern_string(pathname), buf);
}
#endif /* !(defined(_WIN32)) */

/** Return a new list containing the paths that match the pattern
 * <b>pattern</b>. Return NULL on error.
 */
struct smartlist_t *
tor_glob(const char *pattern)
{
  smartlist_t *result;
#ifdef _WIN32
  result = process_glob(pattern, 1, unglob_file_name, handle_glob_win32,
                        no_pattern_after, dir_pattern_after);
#else /* !(defined(_WIN32)) */
  glob_t matches;
  int flags = GLOB_ERR | GLOB_NOSORT;
#ifdef GLOB_ALTDIRFUNC
  /* use functions that call sandbox_intern_string */
  flags |= GLOB_ALTDIRFUNC;
  typedef void *(*gl_opendir)(const char * name);
  typedef struct dirent *(*gl_readdir)(void *);
  typedef void (*gl_closedir)(void *);
  matches.gl_opendir = (gl_opendir) &prot_opendir;
  matches.gl_readdir = (gl_readdir) &readdir;
  matches.gl_closedir = (gl_closedir) &closedir;
  matches.gl_stat = &prot_stat;
  matches.gl_lstat = &prot_lstat;
#endif /* defined(GLOB_ALTDIRFUNC) */
  int ret = glob(pattern, flags, NULL, &matches);
  if (ret == GLOB_NOMATCH) {
    return smartlist_new();
  } else if (ret != 0) {
    return NULL;
  }

  result = smartlist_new();
  size_t i;
  for (i = 0; i < matches.gl_pathc; i++) {
    char *match = tor_strdup(matches.gl_pathv[i]);
    size_t len = strlen(match);
    if (len > 0 && match[len-1] == *PATH_SEPARATOR) {
      match[len-1] = '\0';
    }
    smartlist_add(result, match);
  }
  globfree(&matches);
#endif /* defined(_WIN32) */
  return result;
}

/** Returns true if <b>s</b> contains characters that can be globbed.
 * Returns false otherwise. */
bool
has_glob(const char *s)
{
  int i;
  for (i = 0; s[i]; i++) {
    if (IS_GLOB_CHAR(s, i)) {
      return true;
    }
  }
  return false;
}

/** Returns a list of files that are opened by the tor_glob function when
 * called with <b>pattern</b>. Returns NULL on error. The purpose of this
 * function is to create a list of files to be added to the sandbox white list
 * before the sandbox is enabled. */
struct smartlist_t *
get_glob_opened_files(const char *pattern)
{
  return process_glob(pattern, 0, tor_glob, handle_glob_opened_files,
                      is_file_pred, is_dir_pred);
}
