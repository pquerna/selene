/*
 * Licensed to Selene developers ('Selene') under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * Selene licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "selene.h"
#include "sln_tests.h"
#include "sln_arrays.h"
#include <string.h>

static void arrays_empty(void **state) {
  void *v;
  sln_array_header_t *arr;

  arr = sln_array_make(sln_test_alloc, 0, sizeof(void *));

  assert_int_equal(sln_is_empty_array(arr), 1);

  v = sln_array_push(arr);

  assert_true(v != NULL);

  assert_int_equal(sln_is_empty_array(arr), 0);

  v = sln_array_pop(arr);

  assert_true(v != NULL);

  assert_int_equal(sln_is_empty_array(arr), 1);

  v = sln_array_push(arr);

  assert_true(v != NULL);

  sln_array_clear(arr);

  assert_int_equal(sln_is_empty_array(arr), 1);

  sln_array_destroy(arr);
}

static void arrays_pop(void **state) {
  void *v;
  sln_array_header_t *arr;

  arr = sln_array_make(sln_test_alloc, 0, sizeof(void *));

  assert_int_equal(sln_is_empty_array(arr), 1);

  v = sln_array_pop(arr);

  assert_true(v == NULL);

  v = sln_array_push(arr);

  assert_true(v != NULL);

  v = sln_array_pop(arr);

  assert_true(v != NULL);

  v = sln_array_pop(arr);

  assert_true(v == NULL);

  sln_array_clear(arr);

  v = sln_array_pop(arr);

  assert_true(v == NULL);

  sln_array_destroy(arr);
}

static void arrays_alloc(void **state) {
  int i;
  void *v;
  sln_array_header_t *arr;

  arr = sln_array_make(sln_test_alloc, 2, sizeof(void *));

  for (i = 0; i < 10; i++) {
    SLN_ARRAY_PUSH(arr, void *) = NULL;
  }

  sln_array_clear(arr);

  v = sln_array_pop(arr);

  assert_true(v == NULL);

  sln_array_destroy(arr);
}

SLN_TESTS_START(arrays)
SLN_TESTS_ENTRY(arrays_empty)
SLN_TESTS_ENTRY(arrays_pop)
SLN_TESTS_ENTRY(arrays_alloc)
SLN_TESTS_END()
