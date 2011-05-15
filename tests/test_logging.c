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
#include <stdio.h>

static void logging_levels(void **state)
{
  selene_conf_t *conf = NULL;
  selene_t *ctxt = NULL;
  selene_conf_create(&conf);
  SLN_ERR(selene_conf_use_reasonable_defaults(conf));
  SLN_ERR(selene_server_create(conf, &ctxt));
  SLN_ASSERT_CONTEXT(ctxt);

  sln_log_level_set(ctxt, SLN_LOG_NOTHING);
  assert_int_equal(SLN_LOG_NOTHING, sln_log_level_get(ctxt));
  sln_log_level_set(ctxt, SLN_LOG_EVERYTHING);
  assert_int_equal(SLN_LOG_EVERYTHING, sln_log_level_get(ctxt));
  

  selene_destroy(ctxt);
  selene_conf_destroy(conf);
}

typedef struct log_cb_t {
  const char *cmp;
} log_cb_t;

static selene_error_t*
log_cb(selene_t *s, selene_event_e event, void *baton)
{
  const char *log_msg;
  size_t len;
  log_cb_t *b = (log_cb_t*) baton;

  selene_log_msg_get(s, &log_msg, &len);
  assert_int_equal(38, len);
  assert_string_equal(b->cmp, log_msg+25);

  return SELENE_SUCCESS;
}

static void logging_types(void **state)
{
  selene_conf_t *conf = NULL;
  selene_t *s = NULL;
  log_cb_t b;
  selene_conf_create(&conf);
  SLN_ERR(selene_conf_use_reasonable_defaults(conf));
  SLN_ERR(selene_server_create(conf, &s));
  SLN_ASSERT_CONTEXT(s);

  sln_log_level_set(s, SLN_LOG_EVERYTHING);
  selene_handler_set(s, SELENE_EVENT_LOG_MSG, log_cb, &b);

  b.cmp = "CRT: test:0\n";
  slnCrit(s, "test:%u", 0);

  b.cmp = "ERR: test:1\n";
  slnErr(s, "test:%u", 1);

  b.cmp = "INF: test:2\n";
  slnInfo(s, "test:%u", 2);

  b.cmp = "WRN: test:3\n";
  slnWarn(s, "test:%u", 3);

  b.cmp = "DBG: test:4\n";
  slnDbg(s, "test:%u", 4);

  b.cmp = "TRC: test:5\n";
  slnTrace(s, "test:%u", 5);

  b.cmp = "UNK: test:6\n";
  sln_log_fmt(s, 44, "test:%u", 6);

  sln_log_level_set(s, SLN_LOG_NOTHING);
  slnDbg(s, "test:%u", 4);

  selene_destroy(s);
  selene_conf_destroy(conf);
}

SLN_TESTS_START(logging)
  SLN_TESTS_ENTRY(logging_levels)
  SLN_TESTS_ENTRY(logging_types)
SLN_TESTS_END()
