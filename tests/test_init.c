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

static void init_conf(void **state)
{
  selene_conf_t *conf = NULL;
  SLN_ERR(selene_conf_create(&conf));
  SLN_ASSERT_CONF(conf);
  selene_conf_destroy(conf);
}

static void init_client(void **state)
{
  selene_conf_t *conf = NULL;
  selene_t *ctxt = NULL;
  selene_conf_create(&conf);
  SLN_ERR(selene_conf_use_reasonable_defaults(conf));
  SLN_ERR(selene_client_create(conf, &ctxt));
  SLN_ASSERT_CONTEXT(ctxt);
  selene_destroy(ctxt);
  selene_conf_destroy(conf);
}

static void init_server(void **state)
{
  selene_conf_t *conf = NULL;
  selene_t *ctxt = NULL;
  selene_conf_create(&conf);
  SLN_ERR(selene_conf_use_reasonable_defaults(conf));
  SLN_ERR(selene_server_create(conf, &ctxt));
  SLN_ASSERT_CONTEXT(ctxt);
  selene_destroy(ctxt);
  selene_conf_destroy(conf);
}

static void errors(void **state)
{
  selene_error_t *err = selene_error_create_impl(1, "test", 42, "filename");
  assert_int_equal(err->err, 1);
  assert_int_equal(err->line, 42);
  assert_string_equal(err->msg, "test");
  assert_string_equal(err->file, "filename");
  selene_error_clear(err);

  err = selene_error_createf_impl(2, 43, "xfilename", "foo:%s", "test");
  assert_int_equal(err->err, 2);
  assert_int_equal(err->line, 43);
  assert_string_equal(err->msg, "foo:test");
  assert_string_equal(err->file, "xfilename");
  selene_error_clear(err);

}

SLN_TESTS_START(init)
  SLN_TESTS_ENTRY(init_conf)
  SLN_TESTS_ENTRY(init_client)
  SLN_TESTS_ENTRY(init_server)
  SLN_TESTS_ENTRY(errors)
SLN_TESTS_END()
