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

static void brigade_flatten(void **state)
{
  char buf[80];
  size_t len = sizeof(buf);
  sln_brigade_t *bb;
  sln_bucket_t *e;

  SLN_ERR(sln_brigade_create(&bb));
  SLN_ERR(sln_bucket_create_empty(&e, 40));
  SLN_BRIGADE_INSERT_TAIL(bb, e);
  SLN_ERR(sln_bucket_create_empty(&e, 40));
  SLN_BRIGADE_INSERT_TAIL(bb, e);
  SLN_ERR(sln_brigade_flatten(bb, &buf[0], &len));
  assert_int_equal(len, 80);
  sln_brigade_destroy(bb);
}

static void brigade_pread(void **state)
{
  sln_brigade_t *bb;
  sln_bucket_t *e;

  SLN_ERR(sln_brigade_create(&bb));
  SLN_ERR(sln_bucket_create_empty(&e, 4000));
  SLN_BRIGADE_INSERT_TAIL(bb, e);
  sln_brigade_destroy(bb);

}

SLN_TESTS_START(brigade)
  SLN_TESTS_ENTRY(brigade_flatten)
  SLN_TESTS_ENTRY(brigade_pread)
SLN_TESTS_END()
