/* Copyright (c) 2014, Daniel Martí
 * Copyright (c) 2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CONSDIFF_PRIVATE

#include "or.h"
#include "test.h"

#include "consdiff.h"
#include "log_test_helpers.h"

static void
test_consdiff_smartlist_slice(void *arg)
{
  smartlist_t *sl = smartlist_new();
  smartlist_slice_t *sls;

  /* Create a regular smartlist. */
  (void)arg;
  smartlist_add(sl, (void*)1);
  smartlist_add(sl, (void*)2);
  smartlist_add(sl, (void*)3);
  smartlist_add(sl, (void*)4);
  smartlist_add(sl, (void*)5);

  /* See if the slice was done correctly. */
  sls = smartlist_slice(sl, 2, 5);
  tt_ptr_op(sl, OP_EQ, sls->list);
  tt_ptr_op((void*)3, OP_EQ, smartlist_get(sls->list, sls->offset));
  tt_ptr_op((void*)5, OP_EQ,
      smartlist_get(sls->list, sls->offset + (sls->len-1)));
  tor_free(sls);

  /* See that using -1 as the end does get to the last element. */
  sls = smartlist_slice(sl, 2, -1);
  tt_ptr_op(sl, OP_EQ, sls->list);
  tt_ptr_op((void*)3, OP_EQ, smartlist_get(sls->list, sls->offset));
  tt_ptr_op((void*)5, OP_EQ,
      smartlist_get(sls->list, sls->offset + (sls->len-1)));

 done:
  tor_free(sls);
  smartlist_free(sl);
}

static void
test_consdiff_smartlist_slice_string_pos(void *arg)
{
  smartlist_t *sl = smartlist_new();
  smartlist_slice_t *sls;

  /* Create a regular smartlist. */
  (void)arg;
  smartlist_split_string(sl, "a:d:c:a:b", ":", 0, 0);

  /* See that smartlist_slice_string_pos respects the bounds of the slice. */
  sls = smartlist_slice(sl, 2, 5);
  tt_int_op(3, OP_EQ, smartlist_slice_string_pos(sls, "a"));
  tt_int_op(-1, OP_EQ, smartlist_slice_string_pos(sls, "d"));

 done:
  tor_free(sls);
  if (sl) SMARTLIST_FOREACH(sl, char*, line, tor_free(line));
  smartlist_free(sl);
}

static void
test_consdiff_lcs_lengths(void *arg)
{
  smartlist_t *sl1 = smartlist_new();
  smartlist_t *sl2 = smartlist_new();
  smartlist_slice_t *sls1, *sls2;
  int *lengths1, *lengths2;

  /* Expected lcs lengths in regular and reverse order. */
  int e_lengths1[] = { 0, 1, 2, 3, 3, 4 };
  int e_lengths2[] = { 0, 1, 1, 2, 3, 4 };

  (void)arg;
  smartlist_split_string(sl1, "a:b:c:d:e", ":", 0, 0);
  smartlist_split_string(sl2, "a:c:d:i:e", ":", 0, 0);

  sls1 = smartlist_slice(sl1, 0, -1);
  sls2 = smartlist_slice(sl2, 0, -1);

  lengths1 = lcs_lengths(sls1, sls2, 1);
  lengths2 = lcs_lengths(sls1, sls2, -1);
  tt_mem_op(e_lengths1, OP_EQ, lengths1, sizeof(int) * 6);
  tt_mem_op(e_lengths2, OP_EQ, lengths2, sizeof(int) * 6);

 done:
  tor_free(lengths1);
  tor_free(lengths2);
  tor_free(sls1);
  tor_free(sls2);
  if (sl1) SMARTLIST_FOREACH(sl1, char*, line, tor_free(line));
  if (sl2) SMARTLIST_FOREACH(sl2, char*, line, tor_free(line));
  smartlist_free(sl1);
  smartlist_free(sl2);
}

static void
test_consdiff_trim_slices(void *arg)
{
  smartlist_t *sl1 = smartlist_new();
  smartlist_t *sl2 = smartlist_new();
  smartlist_t *sl3 = smartlist_new();
  smartlist_t *sl4 = smartlist_new();
  smartlist_slice_t *sls1, *sls2, *sls3, *sls4;

  (void)arg;
  smartlist_split_string(sl1, "a:b:b:b:d", ":", 0, 0);
  smartlist_split_string(sl2, "a:c:c:c:d", ":", 0, 0);
  smartlist_split_string(sl3, "a:b:b:b:a", ":", 0, 0);
  smartlist_split_string(sl4, "c:b:b:b:c", ":", 0, 0);

  sls1 = smartlist_slice(sl1, 0, -1);
  sls2 = smartlist_slice(sl2, 0, -1);
  sls3 = smartlist_slice(sl3, 0, -1);
  sls4 = smartlist_slice(sl4, 0, -1);

  /* They should be trimmed by one line at each end. */
  tt_int_op(5, OP_EQ, sls1->len);
  tt_int_op(5, OP_EQ, sls2->len);
  trim_slices(sls1, sls2);
  tt_int_op(3, OP_EQ, sls1->len);
  tt_int_op(3, OP_EQ, sls2->len);

  /* They should not be trimmed at all. */
  tt_int_op(5, OP_EQ, sls3->len);
  tt_int_op(5, OP_EQ, sls4->len);
  trim_slices(sls3, sls4);
  tt_int_op(5, OP_EQ, sls3->len);
  tt_int_op(5, OP_EQ, sls4->len);

 done:
  tor_free(sls1);
  tor_free(sls2);
  tor_free(sls3);
  tor_free(sls4);
  if (sl1) SMARTLIST_FOREACH(sl1, char*, line, tor_free(line));
  if (sl2) SMARTLIST_FOREACH(sl2, char*, line, tor_free(line));
  if (sl3) SMARTLIST_FOREACH(sl3, char*, line, tor_free(line));
  if (sl4) SMARTLIST_FOREACH(sl4, char*, line, tor_free(line));
  smartlist_free(sl1);
  smartlist_free(sl2);
  smartlist_free(sl3);
  smartlist_free(sl4);
}

static void
test_consdiff_set_changed(void *arg)
{
  smartlist_t *sl1 = smartlist_new();
  smartlist_t *sl2 = smartlist_new();
  bitarray_t *changed1 = bitarray_init_zero(4);
  bitarray_t *changed2 = bitarray_init_zero(4);
  smartlist_slice_t *sls1, *sls2;

  (void)arg;
  smartlist_split_string(sl1, "a:b:a:a", ":", 0, 0);
  smartlist_split_string(sl2, "a:a:a:a", ":", 0, 0);

  /* Length of sls1 is 0. */
  sls1 = smartlist_slice(sl1, 0, 0);
  sls2 = smartlist_slice(sl2, 1, 3);
  set_changed(changed1, changed2, sls1, sls2);

  /* The former is not changed, the latter changes all of its elements. */
  tt_assert(!bitarray_is_set(changed1, 0));
  tt_assert(!bitarray_is_set(changed1, 1));
  tt_assert(!bitarray_is_set(changed1, 2));
  tt_assert(!bitarray_is_set(changed1, 3));

  tt_assert(!bitarray_is_set(changed2, 0));
  tt_assert(bitarray_is_set(changed2, 1));
  tt_assert(bitarray_is_set(changed2, 2));
  tt_assert(!bitarray_is_set(changed2, 3));
  bitarray_clear(changed2, 1);
  bitarray_clear(changed2, 2);

  /* Length of sls1 is 1 and its element is in sls2. */
  tor_free(sls1);
  sls1 = smartlist_slice(sl1, 0, 1);
  set_changed(changed1, changed2, sls1, sls2);

  /* The latter changes all elements but the (first) common one. */
  tt_assert(!bitarray_is_set(changed1, 0));
  tt_assert(!bitarray_is_set(changed1, 1));
  tt_assert(!bitarray_is_set(changed1, 2));
  tt_assert(!bitarray_is_set(changed1, 3));

  tt_assert(!bitarray_is_set(changed2, 0));
  tt_assert(!bitarray_is_set(changed2, 1));
  tt_assert(bitarray_is_set(changed2, 2));
  tt_assert(!bitarray_is_set(changed2, 3));
  bitarray_clear(changed2, 2);

  /* Length of sls1 is 1 and its element is not in sls2. */
  tor_free(sls1);
  sls1 = smartlist_slice(sl1, 1, 2);
  set_changed(changed1, changed2, sls1, sls2);

  /* The former changes its element, the latter changes all elements. */
  tt_assert(!bitarray_is_set(changed1, 0));
  tt_assert(bitarray_is_set(changed1, 1));
  tt_assert(!bitarray_is_set(changed1, 2));
  tt_assert(!bitarray_is_set(changed1, 3));

  tt_assert(!bitarray_is_set(changed2, 0));
  tt_assert(bitarray_is_set(changed2, 1));
  tt_assert(bitarray_is_set(changed2, 2));
  tt_assert(!bitarray_is_set(changed2, 3));

 done:
  bitarray_free(changed1);
  bitarray_free(changed2);
  if (sl1) SMARTLIST_FOREACH(sl1, char*, line, tor_free(line));
  if (sl2) SMARTLIST_FOREACH(sl2, char*, line, tor_free(line));
  smartlist_free(sl1);
  smartlist_free(sl2);
  tor_free(sls1);
  tor_free(sls2);
}

static void
test_consdiff_calc_changes(void *arg)
{
  smartlist_t *sl1 = smartlist_new();
  smartlist_t *sl2 = smartlist_new();
  smartlist_slice_t *sls1, *sls2;
  bitarray_t *changed1 = bitarray_init_zero(4);
  bitarray_t *changed2 = bitarray_init_zero(4);

  (void)arg;
  smartlist_split_string(sl1, "a:a:a:a", ":", 0, 0);
  smartlist_split_string(sl2, "a:a:a:a", ":", 0, 0);

  sls1 = smartlist_slice(sl1, 0, -1);
  sls2 = smartlist_slice(sl2, 0, -1);
  calc_changes(sls1, sls2, changed1, changed2);

  /* Nothing should be set to changed. */
  tt_assert(!bitarray_is_set(changed1, 0));
  tt_assert(!bitarray_is_set(changed1, 1));
  tt_assert(!bitarray_is_set(changed1, 2));
  tt_assert(!bitarray_is_set(changed1, 3));

  tt_assert(!bitarray_is_set(changed2, 0));
  tt_assert(!bitarray_is_set(changed2, 1));
  tt_assert(!bitarray_is_set(changed2, 2));
  tt_assert(!bitarray_is_set(changed2, 3));

  SMARTLIST_FOREACH(sl2, char*, line, tor_free(line));
  smartlist_clear(sl2);
  smartlist_split_string(sl2, "a:b:a:b", ":", 0, 0);
  tor_free(sls1);
  tor_free(sls2);
  sls1 = smartlist_slice(sl1, 0, -1);
  sls2 = smartlist_slice(sl2, 0, -1);
  calc_changes(sls1, sls2, changed1, changed2);

  /* Two elements are changed. */
  tt_assert(!bitarray_is_set(changed1, 0));
  tt_assert(bitarray_is_set(changed1, 1));
  tt_assert(bitarray_is_set(changed1, 2));
  tt_assert(!bitarray_is_set(changed1, 3));
  bitarray_clear(changed1, 1);
  bitarray_clear(changed1, 2);

  tt_assert(!bitarray_is_set(changed2, 0));
  tt_assert(bitarray_is_set(changed2, 1));
  tt_assert(!bitarray_is_set(changed2, 2));
  tt_assert(bitarray_is_set(changed2, 3));
  bitarray_clear(changed1, 1);
  bitarray_clear(changed1, 3);

  SMARTLIST_FOREACH(sl2, char*, line, tor_free(line));
  smartlist_clear(sl2);
  smartlist_split_string(sl2, "b:b:b:b", ":", 0, 0);
  tor_free(sls1);
  tor_free(sls2);
  sls1 = smartlist_slice(sl1, 0, -1);
  sls2 = smartlist_slice(sl2, 0, -1);
  calc_changes(sls1, sls2, changed1, changed2);

  /* All elements are changed. */
  tt_assert(bitarray_is_set(changed1, 0));
  tt_assert(bitarray_is_set(changed1, 1));
  tt_assert(bitarray_is_set(changed1, 2));
  tt_assert(bitarray_is_set(changed1, 3));

  tt_assert(bitarray_is_set(changed2, 0));
  tt_assert(bitarray_is_set(changed2, 1));
  tt_assert(bitarray_is_set(changed2, 2));
  tt_assert(bitarray_is_set(changed2, 3));

 done:
  bitarray_free(changed1);
  bitarray_free(changed2);
  if (sl1) SMARTLIST_FOREACH(sl1, char*, line, tor_free(line));
  if (sl2) SMARTLIST_FOREACH(sl2, char*, line, tor_free(line));
  smartlist_free(sl1);
  smartlist_free(sl2);
  tor_free(sls1);
  tor_free(sls2);
}

static void
test_consdiff_get_id_hash(void *arg)
{
  const char *line, *e_hash;
  /* No hash. */
  (void)arg;
  tt_ptr_op(NULL, OP_EQ, get_id_hash("r name"));
  /* The hash contains characters that are not base64. */
  tt_ptr_op(NULL, OP_EQ, get_id_hash( "r name _hash_isnt_base64 etc"));

  line = "r name hash+valid+base64 etc";
  e_hash = line+7;
  tt_ptr_op(e_hash, OP_EQ, get_id_hash(line));

 done:
  ;
}

static void
test_consdiff_is_valid_router_entry(void *arg)
{
  /* Doesn't start with "r ". */
  (void)arg;
  tt_int_op(0, OP_EQ, is_valid_router_entry("foo"));

  /* These are already tested with get_id_hash, but make sure it's run
   * properly. */

  tt_int_op(0, OP_EQ, is_valid_router_entry("r name"));
  tt_int_op(0, OP_EQ, is_valid_router_entry("r name _hash_isnt_base64 etc"));
  tt_int_op(1, OP_EQ, is_valid_router_entry("r name hash+valid+base64 etc"));

 done:
  ;
}

static void
test_consdiff_next_router(void *arg)
{
  smartlist_t *sl = smartlist_new();
  (void)arg;
  smartlist_add(sl, (char*)"foo");
  smartlist_add(sl,
      (char*)"r name hash+longer+than+27+chars+and+valid+base64 etc");
  smartlist_add(sl, (char*)"foo");
  smartlist_add(sl, (char*)"foo");
  smartlist_add(sl,
      (char*)"r name hash+longer+than+27+chars+and+valid+base64 etc");
  smartlist_add(sl, (char*)"foo");

  /* Not currently on a router entry line, finding the next one. */
  tt_int_op(1, OP_EQ, next_router(sl, 0));
  tt_int_op(4, OP_EQ, next_router(sl, 2));

  /* Already at the beginning of a router entry line, ignore it. */
  tt_int_op(4, OP_EQ, next_router(sl, 1));

  /* There are no more router entries, so return the line after the last. */
  tt_int_op(6, OP_EQ, next_router(sl, 4));
  tt_int_op(6, OP_EQ, next_router(sl, 5));

 done:
  smartlist_free(sl);
}

static void
test_consdiff_base64cmp(void *arg)
{
  /* NULL arguments. */
  (void)arg;
  tt_int_op(0, OP_EQ, base64cmp(NULL, NULL));
  tt_int_op(-1, OP_EQ, base64cmp(NULL, "foo"));
  tt_int_op(1, OP_EQ, base64cmp("bar", NULL));

  /* Nil base64 values. */
  tt_int_op(0, OP_EQ, base64cmp("", ""));
  tt_int_op(0, OP_EQ, base64cmp("_", "&"));

  /* Exact same valid strings. */
  tt_int_op(0, OP_EQ, base64cmp("abcABC/+", "abcABC/+"));
  /* Both end with an invalid base64 char other than '\0'. */
  tt_int_op(0, OP_EQ, base64cmp("abcABC/+ ", "abcABC/+ "));
  /* Only one ends with an invalid base64 char other than '\0'. */
  tt_int_op(0, OP_EQ, base64cmp("abcABC/+ ", "abcABC/+"));

  /* Comparisons that would return differently with strcmp(). */
  tt_int_op(-1, OP_EQ, strcmp("/foo", "Afoo"));
  tt_int_op(1, OP_EQ, base64cmp("/foo", "Afoo"));
  tt_int_op(1, OP_EQ, strcmp("Afoo", "0foo"));
  tt_int_op(-1, OP_EQ, base64cmp("Afoo", "0foo"));

  /* Comparisons that would return the same as with strcmp(). */
  tt_int_op(1, OP_EQ, strcmp("afoo", "Afoo"));
  tt_int_op(1, OP_EQ, base64cmp("afoo", "Afoo"));

  /* Different lengths */
  tt_int_op(-1, OP_EQ, base64cmp("afoo", "afooo"));
  tt_int_op(1, OP_EQ, base64cmp("afooo", "afoo"));

 done:
  ;
}

static void
test_consdiff_gen_ed_diff(void *arg)
{
  smartlist_t *cons1=NULL, *cons2=NULL, *diff=NULL;
  int i;
  int free_cons_entries = 0;/* 1 if the cons1 and cons2 contents are
                             * heap-allocated */
  setup_capture_of_logs(LOG_WARN);

  (void)arg;
  cons1 = smartlist_new();
  cons2 = smartlist_new();

  /* Identity hashes are not sorted properly, return NULL. */
  smartlist_add(cons1, (char*)"r name bbbbbbbbbbbbbbbbbbbbbbbbbbb etc");
  smartlist_add(cons1, (char*)"foo");
  smartlist_add(cons1, (char*)"r name aaaaaaaaaaaaaaaaaaaaaaaaaaa etc");
  smartlist_add(cons1, (char*)"bar");

  smartlist_add(cons2, (char*)"r name aaaaaaaaaaaaaaaaaaaaaaaaaaa etc");
  smartlist_add(cons2, (char*)"foo");
  smartlist_add(cons2, (char*)"r name ccccccccccccccccccccccccccc etc");
  smartlist_add(cons2, (char*)"bar");

  diff = gen_ed_diff(cons1, cons2);
  tt_ptr_op(NULL, OP_EQ, diff);
  expect_single_log_msg_containing("Refusing to generate consensus diff "
         "because the base consensus doesn't have its router entries sorted "
         "properly.");

  /* Same, but now with the second consensus. */
  mock_clean_saved_logs();
  diff = gen_ed_diff(cons2, cons1);
  tt_ptr_op(NULL, OP_EQ, diff);
  expect_single_log_msg_containing("Refusing to generate consensus diff "
         "because the target consensus doesn't have its router entries sorted "
         "properly.");

  /* Same as the two above, but with the reversed thing immediately after a
     match. (The code handles this differently) */
  smartlist_del(cons1, 0);
  smartlist_add(cons1, (char*)"r name aaaaaaaaaaaaaaaaaaaaaaaaaaa etc");

  mock_clean_saved_logs();
  diff = gen_ed_diff(cons1, cons2);
  tt_ptr_op(NULL, OP_EQ, diff);
  expect_single_log_msg_containing("Refusing to generate consensus diff "
         "because the base consensus doesn't have its router entries sorted "
         "properly.");

  mock_clean_saved_logs();
  diff = gen_ed_diff(cons2, cons1);
  tt_ptr_op(NULL, OP_EQ, diff);
  expect_single_log_msg_containing("Refusing to generate consensus diff "
         "because the target consensus doesn't have its router entries sorted "
         "properly.");

  /* Identity hashes are repeated, return NULL. */
  smartlist_clear(cons1);

  smartlist_add(cons1, (char*)"r name bbbbbbbbbbbbbbbbbbbbbbbbbbb etc");
  smartlist_add(cons1, (char*)"foo");
  smartlist_add(cons1, (char*)"r name bbbbbbbbbbbbbbbbbbbbbbbbbbb etc");
  smartlist_add(cons1, (char*)"bar");

  mock_clean_saved_logs();
  diff = gen_ed_diff(cons1, cons2);
  tt_ptr_op(NULL, OP_EQ, diff);
  expect_single_log_msg_containing("Refusing to generate consensus diff "
         "because the base consensus doesn't have its router entries sorted "
         "properly.");

  /* We have to add a line that is just a dot, return NULL. */
  smartlist_clear(cons1);
  smartlist_clear(cons2);

  smartlist_add(cons1, (char*)"foo1");
  smartlist_add(cons1, (char*)"foo2");

  smartlist_add(cons2, (char*)"foo1");
  smartlist_add(cons2, (char*)".");
  smartlist_add(cons2, (char*)"foo2");

  mock_clean_saved_logs();
  diff = gen_ed_diff(cons1, cons2);
  tt_ptr_op(NULL, OP_EQ, diff);
  expect_single_log_msg_containing("Cannot generate consensus diff "
         "because one of the lines to be added is \".\".");

#define MAX_LINE_COUNT (10000)
  /* Too many lines to be fed to the quadratic-time function. */
  smartlist_clear(cons1);
  smartlist_clear(cons2);

  for (i=0; i < MAX_LINE_COUNT; ++i) smartlist_add(cons1, (char*)"a");
  for (i=0; i < MAX_LINE_COUNT; ++i) smartlist_add(cons1, (char*)"b");

  mock_clean_saved_logs();
  diff = gen_ed_diff(cons1, cons2);
  tt_ptr_op(NULL, OP_EQ, diff);
  expect_single_log_msg_containing("Refusing to generate consensus diff "
         "because we found too few common router ids.");

  /* We have dot lines, but they don't interfere with the script format. */
  smartlist_clear(cons1);
  smartlist_clear(cons2);

  smartlist_add(cons1, (char*)"foo1");
  smartlist_add(cons1, (char*)".");
  smartlist_add(cons1, (char*)".");
  smartlist_add(cons1, (char*)"foo2");

  smartlist_add(cons2, (char*)"foo1");
  smartlist_add(cons2, (char*)".");
  smartlist_add(cons2, (char*)"foo2");

  diff = gen_ed_diff(cons1, cons2);
  tt_ptr_op(NULL, OP_NE, diff);
  SMARTLIST_FOREACH(diff, char*, line, tor_free(line));
  smartlist_free(diff);

  /* Empty diff tests. */
  smartlist_clear(cons1);
  smartlist_clear(cons2);

  diff = gen_ed_diff(cons1, cons2);
  tt_ptr_op(NULL, OP_NE, diff);
  tt_int_op(0, OP_EQ, smartlist_len(diff));
  smartlist_free(diff);

  smartlist_add(cons1, (char*)"foo");
  smartlist_add(cons1, (char*)"bar");

  smartlist_add(cons2, (char*)"foo");
  smartlist_add(cons2, (char*)"bar");

  diff = gen_ed_diff(cons1, cons2);
  tt_ptr_op(NULL, OP_NE, diff);
  tt_int_op(0, OP_EQ, smartlist_len(diff));
  smartlist_free(diff);

  /* Everything is deleted. */
  smartlist_clear(cons2);

  diff = gen_ed_diff(cons1, cons2);
  tt_ptr_op(NULL, OP_NE, diff);
  tt_int_op(1, OP_EQ, smartlist_len(diff));
  tt_str_op("1,2d", OP_EQ, smartlist_get(diff, 0));

  SMARTLIST_FOREACH(diff, char*, line, tor_free(line));
  smartlist_free(diff);

  /* Everything is added. */
  diff = gen_ed_diff(cons2, cons1);
  tt_ptr_op(NULL, OP_NE, diff);
  tt_int_op(4, OP_EQ, smartlist_len(diff));
  tt_str_op("0a", OP_EQ, smartlist_get(diff, 0));
  tt_str_op("foo", OP_EQ, smartlist_get(diff, 1));
  tt_str_op("bar", OP_EQ, smartlist_get(diff, 2));
  tt_str_op(".", OP_EQ, smartlist_get(diff, 3));

  SMARTLIST_FOREACH(diff, char*, line, tor_free(line));
  smartlist_free(diff);

  /* Everything is changed. */
  smartlist_add(cons2, (char*)"foo2");
  smartlist_add(cons2, (char*)"bar2");
  diff = gen_ed_diff(cons1, cons2);
  tt_ptr_op(NULL, OP_NE, diff);
  tt_int_op(4, OP_EQ, smartlist_len(diff));
  tt_str_op("1,2c", OP_EQ, smartlist_get(diff, 0));
  tt_str_op("foo2", OP_EQ, smartlist_get(diff, 1));
  tt_str_op("bar2", OP_EQ, smartlist_get(diff, 2));
  tt_str_op(".", OP_EQ, smartlist_get(diff, 3));

  SMARTLIST_FOREACH(diff, char*, line, tor_free(line));
  smartlist_free(diff);

  /* Test 'a', 'c' and 'd' together. See that it is done in reverse order. */
  smartlist_clear(cons1);
  smartlist_clear(cons2);
  smartlist_split_string(cons1, "A:B:C:D:E", ":", 0, 0);
  smartlist_split_string(cons2, "A:C:O:E:U", ":", 0, 0);
  free_cons_entries = 1;
  diff = gen_ed_diff(cons1, cons2);
  tt_ptr_op(NULL, OP_NE, diff);
  tt_int_op(7, OP_EQ, smartlist_len(diff));
  tt_str_op("5a", OP_EQ, smartlist_get(diff, 0));
  tt_str_op("U", OP_EQ, smartlist_get(diff, 1));
  tt_str_op(".", OP_EQ, smartlist_get(diff, 2));
  tt_str_op("4c", OP_EQ, smartlist_get(diff, 3));
  tt_str_op("O", OP_EQ, smartlist_get(diff, 4));
  tt_str_op(".", OP_EQ, smartlist_get(diff, 5));
  tt_str_op("2d", OP_EQ, smartlist_get(diff, 6));

  /* TODO: small real use-cases, i.e. consensuses. */

 done:
  teardown_capture_of_logs();
  if (free_cons_entries) {
    if (cons1) SMARTLIST_FOREACH(cons1, char*, line, tor_free(line));
    if (cons2) SMARTLIST_FOREACH(cons2, char*, line, tor_free(line));
  }
  smartlist_free(cons1);
  smartlist_free(cons2);
  if (diff) SMARTLIST_FOREACH(diff, char*, line, tor_free(line));
  smartlist_free(diff);
}

static void
test_consdiff_apply_ed_diff(void *arg)
{
  smartlist_t *cons1=NULL, *cons2=NULL, *diff=NULL;
  (void)arg;
  cons1 = smartlist_new();
  diff = smartlist_new();
  setup_capture_of_logs(LOG_WARN);

  smartlist_split_string(cons1, "A:B:C:D:E", ":", 0, 0);

  /* Command without range. */
  smartlist_add(diff, (char*)"a");
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_EQ, cons2);
  smartlist_clear(diff);
  expect_single_log_msg_containing("an ed command was missing a line number");

  /* Range without command. */
  smartlist_add(diff, (char*)"1");
  mock_clean_saved_logs();
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("a line with no ed command was found");

  smartlist_clear(diff);

  /* Range without end. */
  smartlist_add(diff, (char*)"1,");
  mock_clean_saved_logs();
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("an ed command was missing a range "
                                   "end line number.");

  smartlist_clear(diff);

  /* Incoherent ranges. */
  smartlist_add(diff, (char*)"1,1");
  mock_clean_saved_logs();
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("an invalid range was found");

  smartlist_clear(diff);

  smartlist_add(diff, (char*)"3,2");
  mock_clean_saved_logs();
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("an invalid range was found");

  smartlist_clear(diff);

  /* Script is not in reverse order. */
  smartlist_add(diff, (char*)"1d");
  smartlist_add(diff, (char*)"3d");
  mock_clean_saved_logs();
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("its commands are not properly sorted");

  smartlist_clear(diff);

  /* Script contains unrecognised commands longer than one char. */
  smartlist_add(diff, (char*)"1foo");
  mock_clean_saved_logs();
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("an ed command longer than one char was "
                                   "found");

  smartlist_clear(diff);

  /* Script contains unrecognised commands. */
  smartlist_add(diff, (char*)"1e");
  mock_clean_saved_logs();
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("an unrecognised ed command was found");

  smartlist_clear(diff);

  /* Command that should be followed by at least one line and a ".", but
   * isn't. */
  smartlist_add(diff, (char*)"0a");
  mock_clean_saved_logs();
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("it has an ed command that tries to "
                                   "insert zero lines.");

  /* Now it is followed by a ".", but it inserts zero lines. */
  smartlist_add(diff, (char*)".");
  mock_clean_saved_logs();
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("it has an ed command that tries to "
                                   "insert zero lines.");

  smartlist_clear(diff);

  /* Now it it inserts something, but has no terminator. */
  smartlist_add(diff, (char*)"0a");
  smartlist_add(diff, (char*)"hello");
  mock_clean_saved_logs();
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("lines to be inserted that don't end with "
                                   "a \".\".");

  smartlist_clear(diff);

  /* Test appending text, 'a'. */
  smartlist_split_string(diff, "3a:U:O:.:0a:V:.", ":", 0, 0);
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_NE, cons2);
  tt_int_op(8, OP_EQ, smartlist_len(cons2));
  tt_str_op("V", OP_EQ, smartlist_get(cons2, 0));
  tt_str_op("A", OP_EQ, smartlist_get(cons2, 1));
  tt_str_op("B", OP_EQ, smartlist_get(cons2, 2));
  tt_str_op("C", OP_EQ, smartlist_get(cons2, 3));
  tt_str_op("U", OP_EQ, smartlist_get(cons2, 4));
  tt_str_op("O", OP_EQ, smartlist_get(cons2, 5));
  tt_str_op("D", OP_EQ, smartlist_get(cons2, 6));
  tt_str_op("E", OP_EQ, smartlist_get(cons2, 7));

  SMARTLIST_FOREACH(diff, char*, line, tor_free(line));
  smartlist_clear(diff);
  SMARTLIST_FOREACH(cons2, char*, line, tor_free(line));
  smartlist_free(cons2);

  /* Test deleting text, 'd'. */
  smartlist_split_string(diff, "4d:1,2d", ":", 0, 0);
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_NE, cons2);
  tt_int_op(2, OP_EQ, smartlist_len(cons2));
  tt_str_op("C", OP_EQ, smartlist_get(cons2, 0));
  tt_str_op("E", OP_EQ, smartlist_get(cons2, 1));

  SMARTLIST_FOREACH(diff, char*, line, tor_free(line));
  smartlist_clear(diff);
  SMARTLIST_FOREACH(cons2, char*, line, tor_free(line));
  smartlist_free(cons2);

  /* Test changing text, 'c'. */
  smartlist_split_string(diff, "4c:T:X:.:1, 2c:M:.", ":", 0, 0);
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_NE, cons2);
  tt_int_op(5, OP_EQ, smartlist_len(cons2));
  tt_str_op("M", OP_EQ, smartlist_get(cons2, 0));
  tt_str_op("C", OP_EQ, smartlist_get(cons2, 1));
  tt_str_op("T", OP_EQ, smartlist_get(cons2, 2));
  tt_str_op("X", OP_EQ, smartlist_get(cons2, 3));
  tt_str_op("E", OP_EQ, smartlist_get(cons2, 4));

  SMARTLIST_FOREACH(diff, char*, line, tor_free(line));
  smartlist_clear(diff);
  SMARTLIST_FOREACH(cons2, char*, line, tor_free(line));
  smartlist_free(cons2);

  /* Test 'a', 'd' and 'c' together. */
  smartlist_split_string(diff, "4c:T:X:.:2d:0a:M:.", ":", 0, 0);
  cons2 = apply_ed_diff(cons1, diff);
  tt_ptr_op(NULL, OP_NE, cons2);
  tt_int_op(6, OP_EQ, smartlist_len(cons2));
  tt_str_op("M", OP_EQ, smartlist_get(cons2, 0));
  tt_str_op("A", OP_EQ, smartlist_get(cons2, 1));
  tt_str_op("C", OP_EQ, smartlist_get(cons2, 2));
  tt_str_op("T", OP_EQ, smartlist_get(cons2, 3));
  tt_str_op("X", OP_EQ, smartlist_get(cons2, 4));
  tt_str_op("E", OP_EQ, smartlist_get(cons2, 5));

 done:
  teardown_capture_of_logs();
  if (cons1) SMARTLIST_FOREACH(cons1, char*, line, tor_free(line));
  if (cons2) SMARTLIST_FOREACH(cons2, char*, line, tor_free(line));
  smartlist_free(cons1);
  smartlist_free(cons2);
  if (diff) SMARTLIST_FOREACH(diff, char*, line, tor_free(line));
  smartlist_free(diff);
}

static void
test_consdiff_gen_diff(void *arg)
{
  char *cons1_str=NULL, *cons2_str=NULL;
  smartlist_t *cons1=NULL, *cons2=NULL, *diff=NULL;
  consensus_digest_t digests1, digests2;
  (void)arg;
  cons1 = smartlist_new();
  cons2 = smartlist_new();

  /* Identity hashes are not sorted properly, return NULL.
   * Already tested in gen_ed_diff, but see that a NULL ed diff also makes
   * gen_diff return NULL. */
  cons1_str = tor_strdup(
      "network-status-version foo\n"
      "r name bbbbbbbbbbbbbbbbb etc\nfoo\n"
      "r name aaaaaaaaaaaaaaaaa etc\nbar\n"
      "directory-signature foo bar\nbar\n"
      );
  cons2_str = tor_strdup(
      "network-status-version foo\n"
      "r name aaaaaaaaaaaaaaaaa etc\nfoo\n"
      "r name ccccccccccccccccc etc\nbar\n"
      "directory-signature foo bar\nbar\n"
      );

  tt_int_op(0, OP_EQ,
      consensus_compute_digest(cons1_str, &digests1));
  tt_int_op(0, OP_EQ,
      consensus_compute_digest(cons2_str, &digests2));

  tor_split_lines(cons1, cons1_str, (int)strlen(cons1_str));
  tor_split_lines(cons2, cons2_str, (int)strlen(cons2_str));

  diff = consdiff_gen_diff(cons1, cons2, &digests1, &digests2);
  tt_ptr_op(NULL, OP_EQ, diff);

  /* Check that the headers are done properly. */
  tor_free(cons1_str);
  cons1_str = tor_strdup(
      "network-status-version foo\n"
      "r name ccccccccccccccccc etc\nfoo\n"
      "r name eeeeeeeeeeeeeeeee etc\nbar\n"
      "directory-signature foo bar\nbar\n"
      );
  tt_int_op(0, OP_EQ,
      consensus_compute_digest(cons1_str, &digests1));
  smartlist_clear(cons1);
  tor_split_lines(cons1, cons1_str, (int)strlen(cons1_str));
  diff = consdiff_gen_diff(cons1, cons2, &digests1, &digests2);
  tt_ptr_op(NULL, OP_NE, diff);
  tt_int_op(7, OP_EQ, smartlist_len(diff));
  tt_str_op("network-status-diff-version 1", OP_EQ, smartlist_get(diff, 0));
  tt_str_op("hash "
      "06646D6CF563A41869D3B02E73254372AE3140046C5E7D83C9F71E54976AF9B4 "
      "7AFECEFA4599BA33D603653E3D2368F648DF4AC4723929B0F7CF39281596B0C1",
      OP_EQ, smartlist_get(diff, 1));
  tt_str_op("3,4d", OP_EQ, smartlist_get(diff, 2));
  tt_str_op("1a", OP_EQ, smartlist_get(diff, 3));
  tt_str_op("r name aaaaaaaaaaaaaaaaa etc", OP_EQ, smartlist_get(diff, 4));
  tt_str_op("foo", OP_EQ, smartlist_get(diff, 5));
  tt_str_op(".", OP_EQ, smartlist_get(diff, 6));

  /* TODO: small real use-cases, i.e. consensuses. */

 done:
  tor_free(cons1_str);
  tor_free(cons2_str);
  smartlist_free(cons1);
  smartlist_free(cons2);
  if (diff) SMARTLIST_FOREACH(diff, char*, line, tor_free(line));
  smartlist_free(diff);
}

static void
test_consdiff_apply_diff(void *arg)
{
  smartlist_t *cons1=NULL, *diff=NULL;
  char *cons1_str=NULL, *cons2 = NULL;
  consensus_digest_t digests1;
  (void)arg;
  cons1 = smartlist_new();
  diff = smartlist_new();
  setup_capture_of_logs(LOG_INFO);

  cons1_str = tor_strdup(
      "network-status-version foo\n"
      "r name ccccccccccccccccc etc\nfoo\n"
      "r name eeeeeeeeeeeeeeeee etc\nbar\n"
      "directory-signature foo bar\nbar\n"
      );
  tt_int_op(0, OP_EQ,
      consensus_compute_digest(cons1_str, &digests1));
  tor_split_lines(cons1, cons1_str, (int)strlen(cons1_str));

  /* diff doesn't have enough lines. */
  cons2 = consdiff_apply_diff(cons1, diff, &digests1);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("too short")

  /* first line doesn't match format-version string. */
  smartlist_add(diff, (char*)"foo-bar");
  smartlist_add(diff, (char*)"header-line");
  mock_clean_saved_logs();
  cons2 = consdiff_apply_diff(cons1, diff, &digests1);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("format is not known")

  /* The first word of the second header line is not "hash". */
  smartlist_clear(diff);
  smartlist_add(diff, (char*)"network-status-diff-version 1");
  smartlist_add(diff, (char*)"word a b");
  smartlist_add(diff, (char*)"x");
  mock_clean_saved_logs();
  cons2 = consdiff_apply_diff(cons1, diff, &digests1);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("does not include the necessary digests")

  /* Wrong number of words after "hash". */
  smartlist_clear(diff);
  smartlist_add(diff, (char*)"network-status-diff-version 1");
  smartlist_add(diff, (char*)"hash a b c");
  mock_clean_saved_logs();
  cons2 = consdiff_apply_diff(cons1, diff, &digests1);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("does not include the necessary digests")

  /* base16 digests do not have the expected length. */
  smartlist_clear(diff);
  smartlist_add(diff, (char*)"network-status-diff-version 1");
  smartlist_add(diff, (char*)"hash aaa bbb");
  mock_clean_saved_logs();
  cons2 = consdiff_apply_diff(cons1, diff, &digests1);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("includes base16-encoded digests of "
                                   "incorrect size")

  /* base16 digests contain non-base16 characters. */
  smartlist_clear(diff);
  smartlist_add(diff, (char*)"network-status-diff-version 1");
  smartlist_add(diff, (char*)"hash"
      " ????????????????????????????????????????????????????????????????"
      " ----------------------------------------------------------------");
  mock_clean_saved_logs();
  cons2 = consdiff_apply_diff(cons1, diff, &digests1);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("includes malformed digests")

  /* Invalid ed diff.
   * As tested in apply_ed_diff, but check that apply_diff does return NULL if
   * the ed diff can't be applied. */
  smartlist_clear(diff);
  smartlist_add(diff, (char*)"network-status-diff-version 1");
  smartlist_add(diff, (char*)"hash"
      /* sha3 of cons1. */
      " 06646D6CF563A41869D3B02E73254372AE3140046C5E7D83C9F71E54976AF9B4"
      /* sha256 of cons2. */
      " 635D34593020C08E5ECD865F9986E29D50028EFA62843766A8197AD228A7F6AA");
  smartlist_add(diff, (char*)"foobar");
  mock_clean_saved_logs();
  cons2 = consdiff_apply_diff(cons1, diff, &digests1);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_single_log_msg_containing("because an ed command was missing a line "
                                   "number")

  /* Base consensus doesn't match its digest as found in the diff. */
  smartlist_clear(diff);
  smartlist_add(diff, (char*)"network-status-diff-version 1");
  smartlist_add(diff, (char*)"hash"
      /* bogus sha256. */
      " 3333333333333333333333333333333333333333333333333333333333333333"
      /* sha256 of cons2. */
      " 635D34593020C08E5ECD865F9986E29D50028EFA62843766A8197AD228A7F6AA");
  mock_clean_saved_logs();
  cons2 = consdiff_apply_diff(cons1, diff, &digests1);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_log_msg_containing("base consensus doesn't match the digest "
                            "as found");

  /* Resulting consensus doesn't match its digest as found in the diff. */
  smartlist_clear(diff);
  smartlist_add(diff, (char*)"network-status-diff-version 1");
  smartlist_add(diff, (char*)"hash"
      /* sha3 of cons1. */
      " 06646D6CF563A41869D3B02E73254372AE3140046C5E7D83C9F71E54976AF9B4"
      /* bogus sha3. */
      " 3333333333333333333333333333333333333333333333333333333333333333");
  mock_clean_saved_logs();
  cons2 = consdiff_apply_diff(cons1, diff, &digests1);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_log_msg_containing("resulting consensus doesn't match the "
                            "digest as found");

#if 0
  /* XXXX No longer possible, since we aren't using the other algorithm. */
  /* Resulting consensus digest cannot be computed */
  smartlist_clear(diff);
  smartlist_add(diff, (char*)"network-status-diff-version 1");
  smartlist_add(diff, (char*)"hash"
      /* sha3 of cons1. */
      " 06646D6CF563A41869D3B02E73254372AE3140046C5E7D83C9F71E54976AF9B4"
      /* bogus sha3. */
      " 3333333333333333333333333333333333333333333333333333333333333333");
  smartlist_add(diff, (char*)"1,2d"); // remove starting line
  mock_clean_saved_logs();
  cons2 = consdiff_apply_diff(cons1, diff, &digests1);
  tt_ptr_op(NULL, OP_EQ, cons2);
  expect_log_msg_containing("Could not compute digests of the consensus "
                            "resulting from applying a consensus diff.");
#endif

  /* Very simple test, only to see that nothing errors. */
  smartlist_clear(diff);
  smartlist_add(diff, (char*)"network-status-diff-version 1");
  smartlist_add(diff, (char*)"hash"
      /* sha3 of cons1. */
      " 06646D6CF563A41869D3B02E73254372AE3140046C5E7D83C9F71E54976AF9B4"
      /* sha3 of cons2. */
      " 90A418881B2FCAB3D9E60EE02E4D666D56CFA38F8A3B7AA3E0ADBA530DDA9353");
  smartlist_add(diff, (char*)"3c");
  smartlist_add(diff, (char*)"sample");
  smartlist_add(diff, (char*)".");
  cons2 = consdiff_apply_diff(cons1, diff, &digests1);
  tt_ptr_op(NULL, OP_NE, cons2);
  tt_str_op(
      "network-status-version foo\n"
      "r name ccccccccccccccccc etc\nsample\n"
      "r name eeeeeeeeeeeeeeeee etc\nbar\n"
      "directory-signature foo bar\nbar\n", OP_EQ,
      cons2);
  tor_free(cons2);

  /* Check that lowercase letters in base16-encoded digests work too. */
  smartlist_clear(diff);
  smartlist_add(diff, (char*)"network-status-diff-version 1");
  smartlist_add(diff, (char*)"hash"
      /* sha3 of cons1. */
      " 06646d6cf563a41869d3b02e73254372ae3140046c5e7d83c9f71e54976af9b4"
      /* sha3 of cons2. */
      " 90a418881b2fcab3d9e60ee02e4d666d56cfa38f8a3b7aa3e0adba530dda9353");
  smartlist_add(diff, (char*)"3c");
  smartlist_add(diff, (char*)"sample");
  smartlist_add(diff, (char*)".");
  cons2 = consdiff_apply_diff(cons1, diff, &digests1);
  tt_ptr_op(NULL, OP_NE, cons2);
  tt_str_op(
      "network-status-version foo\n"
      "r name ccccccccccccccccc etc\nsample\n"
      "r name eeeeeeeeeeeeeeeee etc\nbar\n"
      "directory-signature foo bar\nbar\n", OP_EQ,
      cons2);
  tor_free(cons2);

  smartlist_clear(diff);

 done:
  teardown_capture_of_logs();
  tor_free(cons1_str);
  smartlist_free(cons1);
  smartlist_free(diff);
}

#define CONSDIFF_LEGACY(name)                                          \
  { #name, test_consdiff_ ## name , 0, NULL, NULL }

struct testcase_t consdiff_tests[] = {
  CONSDIFF_LEGACY(smartlist_slice),
  CONSDIFF_LEGACY(smartlist_slice_string_pos),
  CONSDIFF_LEGACY(lcs_lengths),
  CONSDIFF_LEGACY(trim_slices),
  CONSDIFF_LEGACY(set_changed),
  CONSDIFF_LEGACY(calc_changes),
  CONSDIFF_LEGACY(get_id_hash),
  CONSDIFF_LEGACY(is_valid_router_entry),
  CONSDIFF_LEGACY(next_router),
  CONSDIFF_LEGACY(base64cmp),
  CONSDIFF_LEGACY(gen_ed_diff),
  CONSDIFF_LEGACY(apply_ed_diff),
  CONSDIFF_LEGACY(gen_diff),
  CONSDIFF_LEGACY(apply_diff),
  END_OF_TESTCASES
};

