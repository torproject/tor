/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file conffile.h
 *
 * \brief Read configuration files from disk, with full `%include` support.
 **/

#include "lib/fs/conffile.h"

#include "lib/container/smartlist.h"
#include "lib/encoding/confline.h"
#include "lib/fs/dir.h"
#include "lib/fs/files.h"
#include "lib/fs/path.h"
#include "lib/log/log.h"
#include "lib/malloc/malloc.h"
#include "lib/string/printf.h"

static smartlist_t *config_get_file_list(const char *path,
                                         smartlist_t *opened_files);
static int config_get_included_config(const char *path, int recursion_level,
                                      int extended, config_line_t **config,
                                      config_line_t **config_last,
                                      smartlist_t *opened_lst);
static int config_process_include(const char *path, int recursion_level,
                                  int extended, config_line_t **list,
                                  config_line_t **list_last,
                                  smartlist_t *opened_lst);

/** Helper: parse the config string and strdup into key/value
 * strings. Set *result to the list, or NULL if parsing the string
 * failed. Set *has_include to 1 if <b>result</b> has values from
 * %included files. <b>opened_lst</b> will have a list of opened files if
 * provided. Return 0 on success, -1 on failure. Warn and ignore any
 * misformatted lines.
 *
 * If <b>extended</b> is set, then treat keys beginning with / and with + as
 * indicating "clear" and "append" respectively. */
int
config_get_lines_include(const char *string, config_line_t **result,
                         int extended, int *has_include,
                         smartlist_t *opened_lst)
{
  return config_get_lines_aux(string, result, extended, 1, has_include,
                              opened_lst, 1, NULL, config_process_include);
}

/** Returns a list of configuration files present on paths that match
 * <b>pattern</b>. The pattern is expanded and then all the paths are
 * processed. A path can be a file or a directory. If it is a file, that file
 * will be added to the list to be returned. If it is a directory,
 * all paths for files on that directory root (no recursion) except for files
 * whose name starts with a dot will be added to the list to be returned.
 * <b>opened_files</b> will have a list of files opened by this function
 * if provided. Return NULL on failure. Ignores empty files.
 */
static smartlist_t *
config_get_file_list(const char *pattern, smartlist_t *opened_files)
{
  smartlist_t *matches = tor_glob(pattern);
  if (!matches) {
    return NULL;
  }

  // if it is not a glob, return error when the path is missing
  if (!has_glob(pattern) && smartlist_len(matches) == 0) {
    smartlist_free(matches);
    return NULL;
  }

  if (opened_files) {
    smartlist_t *glob_opened = get_glob_opened_files(pattern);
    if (!glob_opened) {
      SMARTLIST_FOREACH(matches, char *, f, tor_free(f));
      smartlist_free(matches);
      return NULL;
    }
    smartlist_add_all(opened_files, glob_opened);
    smartlist_free(glob_opened);
  }

  smartlist_sort_strings(matches);
  int error_found = 0;
  smartlist_t *file_list = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(matches, char *, path) {
    if (opened_files) {
      smartlist_add_strdup(opened_files, path);
    }

    file_status_t file_type = file_status(path);
    if (file_type == FN_FILE) {
      smartlist_add_strdup(file_list, path);
    } else if (file_type == FN_DIR) {
      smartlist_t *all_files = tor_listdir(path);
      if (!all_files) {
        error_found = 1;
        break;
      }
      smartlist_sort_strings(all_files);
      SMARTLIST_FOREACH_BEGIN(all_files, char *, f) {
        if (f[0] == '.') {
          tor_free(f);
          continue;
        }

        char *fullname;
        tor_asprintf(&fullname, "%s"PATH_SEPARATOR"%s", path, f);
        tor_free(f);

        if (opened_files) {
          smartlist_add_strdup(opened_files, fullname);
        }

        if (file_status(fullname) != FN_FILE) {
          tor_free(fullname);
          continue;
        }
        smartlist_add(file_list, fullname);
      } SMARTLIST_FOREACH_END(f);
      smartlist_free(all_files);
    } else if (file_type == FN_EMPTY) {
        continue;
    } else {
      error_found = 1;
      break;
    }
  } SMARTLIST_FOREACH_END(path);

  SMARTLIST_FOREACH(matches, char *, f, tor_free(f));
  smartlist_free(matches);

  if (error_found) {
    SMARTLIST_FOREACH(file_list, char *, f, tor_free(f));
    smartlist_free(file_list);
    file_list = NULL;
  }

  return file_list;
}

/** Creates a list of config lines present on included <b>path</b>.
 * Set <b>config</b> to the list and <b>config_last</b> to the last element of
 * <b>config</b>. <b>opened_lst</b> will have a list of opened files if
 * provided. Return 0 on success, -1 on failure. */
static int
config_get_included_config(const char *path, int recursion_level, int extended,
                           config_line_t **config, config_line_t **config_last,
                           smartlist_t *opened_lst)
{
  char *included_conf = read_file_to_str(path, 0, NULL);
  if (!included_conf) {
    return -1;
  }

  if (config_get_lines_aux(included_conf, config, extended, 1, NULL,
                           opened_lst, recursion_level+1, config_last,
                           config_process_include) < 0) {
    tor_free(included_conf);
    return -1;
  }

  tor_free(included_conf);
  return 0;
}

/** Process an %include <b>pattern</b> in a config file. Set <b>list</b> to the
 * list of configuration settings obtained and <b>list_last</b> to the last
 * element of the same list. <b>opened_lst</b> will have a list of opened
 * files if provided. Return 0 on success, -1 on failure. */
static int
config_process_include(const char *pattern, int recursion_level, int extended,
                       config_line_t **list, config_line_t **list_last,
                       smartlist_t *opened_lst)
{
  config_line_t *ret_list = NULL;
  config_line_t **next = &ret_list;

  smartlist_t *config_files = config_get_file_list(pattern, opened_lst);
  if (!config_files) {
    return -1;
  }

  int rv = -1;
  SMARTLIST_FOREACH_BEGIN(config_files, const char *, config_file) {
    log_notice(LD_CONFIG, "Loading configuration file \"%s\".", config_file);
    config_line_t *included_config = NULL;
    if (config_get_included_config(config_file, recursion_level, extended,
                                   &included_config, list_last,
                                   opened_lst) < 0) {
      goto done;
    }

    *next = included_config;
    if (*list_last)
      next = &(*list_last)->next;

  } SMARTLIST_FOREACH_END(config_file);
  *list = ret_list;
  rv = 0;

 done:
  SMARTLIST_FOREACH(config_files, char *, f, tor_free(f));
  smartlist_free(config_files);
  return rv;
}
