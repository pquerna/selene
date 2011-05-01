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
#include "sln_buckets.h"
#include <string.h>

static void
bucket_empty(void **state)
{
  sln_bucket_t *e;
  SLN_ERR(sln_bucket_create_empty(&e, 4000));
  sln_bucket_destroy(e);
}

static void
bucket_with_bytes(void **state)
{
  char *data = malloc(7);
  strncat(data, "foobar", 7);
  sln_bucket_t *e;
  SLN_ERR(sln_bucket_create_with_bytes(&e, data, strlen(data)));
  assert_memory_equal(data, e->data, 6);
  sln_bucket_destroy(e);
  free(data);
}

static void
bucket_copy_bytes(void **state)
{
  const char *data = "foobar";
  sln_bucket_t *e;
  SLN_ERR(sln_bucket_create_copy_bytes(&e, data, strlen(data)));
  assert_memory_equal(data, e->data, 6);
  sln_bucket_destroy(e);
}

SLN_TESTS_START(buckets)
  SLN_TESTS_ENTRY(bucket_empty)
  SLN_TESTS_ENTRY(bucket_with_bytes)
  SLN_TESTS_ENTRY(bucket_copy_bytes)
SLN_TESTS_END()
