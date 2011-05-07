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
#include "sln_brigades.h"
#include <string.h>

static void brigade_operations(void **state)
{
  sln_brigade_t *bb;
  sln_bucket_t *e;
  SLN_ERR(sln_brigade_create(&bb));
  assert_int_equal(sln_brigade_size(bb), 0);
  SLN_ERR(sln_bucket_create_empty(&e, 40));
  SLN_BRIGADE_INSERT_TAIL(bb, e);
  assert_int_equal(sln_brigade_size(bb), 40);
  SLN_BUCKET_REMOVE(e);
  assert_int_equal(sln_brigade_size(bb), 0);
  sln_brigade_destroy(bb);
}



static void brigade_flatten(void **state)
{
  char buf[80];
  char bufcmp[80];
  size_t len = sizeof(buf);
  sln_brigade_t *bb;
  sln_bucket_t *e1;
  sln_bucket_t *e2;

  SLN_ERR(sln_brigade_create(&bb));
  SLN_ERR(sln_bucket_create_empty(&e1, 40));
  memset(e1->data, 'A', e1->size);
  SLN_BRIGADE_INSERT_TAIL(bb, e1);
  SLN_ERR(sln_bucket_create_empty(&e2, 40));
  memset(e2->data, 'B', e2->size);
  SLN_BRIGADE_INSERT_TAIL(bb, e2);
  SLN_ERR(sln_brigade_flatten(bb, &buf[0], &len));
  assert_int_equal(len, 80);
  sln_brigade_destroy(bb);

  memset(&bufcmp[0], 'A', 40);
  memset(&bufcmp[0]+40, 'B', 40);
  assert_memory_equal(buf, bufcmp, 80);
}

static void brigade_flatten_leftover(void **state)
{
  char buf[80];
  char bufcmp[80];
  char buf2[2];
  char bufcmp2[2];
  size_t len = sizeof(buf);
  size_t len2 = sizeof(buf2);
  sln_brigade_t *bb;
  sln_bucket_t *e1;
  sln_bucket_t *e2;

  SLN_ERR(sln_brigade_create(&bb));
  SLN_ERR(sln_bucket_create_empty(&e1, 40));
  memset(e1->data, 'A', e1->size);
  SLN_BRIGADE_INSERT_TAIL(bb, e1);
  SLN_ERR(sln_bucket_create_empty(&e2, 42));
  memset(e2->data, 'B', e2->size);
  SLN_BRIGADE_INSERT_TAIL(bb, e2);
  SLN_ERR(sln_brigade_flatten(bb, &buf[0], &len));
  assert_int_equal(len, 80);
  assert_int_equal(sln_brigade_size(bb), 2);
  SLN_ERR(sln_brigade_flatten(bb, &buf2[0], &len2));
  assert_int_equal(len2, 2);
  sln_brigade_destroy(bb);

  memset(&bufcmp[0], 'A', 40);
  memset(&bufcmp[0]+40, 'B', 40);
  assert_memory_equal(buf, bufcmp, 80);

  memset(&bufcmp2[0], 'B', 2);
  assert_memory_equal(buf2, bufcmp2, 2);
}

static void brigade_pread_simple(void **state)
{
  sln_brigade_t *bb;
  sln_bucket_t *e;
  char buf[5];
  size_t len = 0;

  SLN_ERR(sln_brigade_create(&bb));
  SLN_ERR(sln_bucket_create_empty(&e, 20));
  SLN_BRIGADE_INSERT_TAIL(bb, e);
  memset(e->data, 'B', e->size);
  memset(e->data, 'A', 1);

  SLN_ERR(sln_brigade_pread_bytes(bb, 0, 1, &buf[0], &len));
  assert_int_equal(len, 1);
  assert_memory_equal(buf, "A", 1);

  SLN_ERR(sln_brigade_pread_bytes(bb, 1, 1, &buf[0], &len));
  assert_int_equal(len, 1);
  assert_memory_equal(buf, "B", 1);

  SLN_ERR(sln_brigade_pread_bytes(bb, 0, 2, &buf[0], &len));
  assert_int_equal(len, 2);
  assert_memory_equal(buf, "AB", 2);

  SLN_ERR(sln_brigade_pread_bytes(bb, 2, 2, &buf[0], &len));
  assert_int_equal(len, 2);
  assert_memory_equal(buf, "BB", 2);

  sln_brigade_destroy(bb);
}

static void brigade_pread_more_buckets(void **state)
{
  sln_brigade_t *bb;
  sln_bucket_t *e1;
  sln_bucket_t *e2;
  char buf[20];
  size_t len = 0;

  SLN_ERR(sln_brigade_create(&bb));
  SLN_ERR(sln_bucket_create_empty(&e1, 10));
  SLN_BRIGADE_INSERT_TAIL(bb, e1);
  memset(e1->data, 'A', e1->size);

  SLN_ERR(sln_bucket_create_empty(&e2, 10));
  SLN_BRIGADE_INSERT_TAIL(bb, e2);
  memset(e2->data, 'B', e2->size);

  SLN_ERR(sln_brigade_pread_bytes(bb, 9, 1, &buf[0], &len));
  assert_int_equal(len, 1);
  assert_memory_equal(buf, "A", 1);

  SLN_ERR(sln_brigade_pread_bytes(bb, 11, 1, &buf[0], &len));
  assert_int_equal(len, 1);
  assert_memory_equal(buf, "B", 1);

  SLN_ERR(sln_brigade_pread_bytes(bb, 9, 2, &buf[0], &len));
  assert_int_equal(len, 2);
  assert_memory_equal(buf, "AB", 2);

  SLN_ERR(sln_brigade_pread_bytes(bb, 11, 2, &buf[0], &len));
  assert_int_equal(len, 2);
  assert_memory_equal(buf, "BB", 2);

  SLN_ERR(sln_brigade_pread_bytes(bb, 0, 20, &buf[0], &len));
  assert_int_equal(len, 20);
  assert_memory_equal(buf, "AAAAAAAAAABBBBBBBBBB", 20);

  sln_brigade_destroy(bb);
}

static void brigade_copy_into(void **state)
{
  sln_brigade_t *source;
  sln_brigade_t *dest;
  sln_bucket_t *e1;
  char buf[20];
  size_t len = 0;

  SLN_ERR(sln_brigade_create(&source));
  SLN_ERR(sln_bucket_create_empty(&e1, 10));
  SLN_BRIGADE_INSERT_TAIL(source, e1);
  memset(e1->data, 'A', e1->size);

  SLN_ERR(sln_brigade_create(&dest));
  SLN_ERR(sln_brigade_copy_into(source, 0, 10, dest));
  assert_int_equal(sln_brigade_size(dest), 10);
  SLN_ERR(sln_brigade_pread_bytes(dest, 0, 10, &buf[0], &len));
  assert_memory_equal(buf, "AAAAAAAAAA", 2);
  sln_brigade_clear(dest);

  SLN_ERR(sln_brigade_create(&dest));
  SLN_ERR(sln_brigade_copy_into(source, 2, 4, dest));
  assert_int_equal(sln_brigade_size(dest), 4);
  SLN_ERR(sln_brigade_pread_bytes(dest, 0, 4, &buf[0], &len));
  assert_memory_equal(buf, "AAAA", 4);
  sln_brigade_clear(dest);

}

SLN_TESTS_START(brigade)
  SLN_TESTS_ENTRY(brigade_operations)
  SLN_TESTS_ENTRY(brigade_flatten)
  SLN_TESTS_ENTRY(brigade_flatten_leftover)
  SLN_TESTS_ENTRY(brigade_pread_simple)
  SLN_TESTS_ENTRY(brigade_pread_more_buckets)
  SLN_TESTS_ENTRY(brigade_copy_into)
SLN_TESTS_END()
