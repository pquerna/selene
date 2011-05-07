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
#include "sln_tok.h"
#include <string.h>

typedef struct baton_t {
  int count;
} baton_t;

static selene_error_t*
tok_nowork_cb(sln_tok_value_t *v, void *baton_)
{
  baton_t *baton = (baton_t *)baton_;
  baton->count++;
  //v->next = TOK_SINGLE_BYTE;
  v->next = TOK_DONE;
  return SELENE_SUCCESS;
}

static void tok_nowork(void **state)
{
  sln_brigade_t *bb;
  baton_t baton;
  baton.count = 0;

  SLN_ERR(sln_brigade_create(&bb));
  SLN_ERR(sln_tok_parser(bb, tok_nowork_cb, &baton));

  assert_int_equal(1, baton.count);
  sln_brigade_destroy(bb);
}

static selene_error_t*
tok_bytes_cb(sln_tok_value_t *v, void *baton_)
{
  baton_t *baton = (baton_t *)baton_;
  if (baton->count == 0) {
    v->next = TOK_COPY_BYTES;
    v->wantlen = 4;
  }
  if (baton->count == 1) {
    v->next = TOK_DONE;
    assert_memory_equal(v->v.bytes, "AAAA", 4);
  }
  baton->count++;
  return SELENE_SUCCESS;
}

static void tok_bytes(void **state)
{
  sln_brigade_t *bb;
  sln_bucket_t *e1;
  baton_t baton;
  baton.count = 0;

  SLN_ERR(sln_brigade_create(&bb));
  SLN_ERR(sln_bucket_create_empty(&e1, 10));
  SLN_BRIGADE_INSERT_TAIL(bb, e1);
  memset(e1->data, 'A', e1->size);
  SLN_ERR(sln_tok_parser(bb, tok_bytes_cb, &baton));
  assert_int_equal(2, baton.count);
  sln_brigade_destroy(bb);
}


static selene_error_t*
tok_copy_brigade_cb(sln_tok_value_t *v, void *baton_)
{
  baton_t *baton = (baton_t *)baton_;
  if (baton->count == 0) {
    v->next = TOK_COPY_BRIGADE;
    v->wantlen = 4;
  }
  if (baton->count == 1) {
    char buf[4];
    size_t len = sizeof(buf);
    v->next = TOK_DONE;
    SLN_ERR(sln_brigade_flatten(v->v.bb, &buf[0], &len));
    assert_memory_equal(buf, "AAAA", 4);
  }
  baton->count++;
  return SELENE_SUCCESS;
}

static void tok_copy_brigade(void **state)
{
  sln_brigade_t *bb;
  sln_bucket_t *e1;
  baton_t baton;
  baton.count = 0;

  SLN_ERR(sln_brigade_create(&bb));
  SLN_ERR(sln_bucket_create_empty(&e1, 10));
  SLN_BRIGADE_INSERT_TAIL(bb, e1);
  memset(e1->data, 'A', e1->size);
  SLN_ERR(sln_tok_parser(bb, tok_copy_brigade_cb, &baton));
  assert_int_equal(2, baton.count);
  sln_brigade_destroy(bb);
}

SLN_TESTS_START(tok)
  SLN_TESTS_ENTRY(tok_nowork)
  SLN_TESTS_ENTRY(tok_bytes)
  SLN_TESTS_ENTRY(tok_copy_brigade)
SLN_TESTS_END()
