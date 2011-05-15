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
#include <stdio.h>
#include "../lib/backends/native/native.h"
#include "../lib/backends/native/alert_messages.h"

static char alert_close_notify[] = {
  0x01, 0x00
};

static void alert_msg(void **state)
{
  selene_error_t *err;
  sln_native_baton_t *baton;
  selene_conf_t *conf = NULL;
  selene_t *s = NULL;
  sln_bucket_t *e1;
  size_t maxlen = sizeof(alert_close_notify);
  size_t i;

  selene_conf_create(&conf);
  SLN_ERR(selene_conf_use_reasonable_defaults(conf));
  SLN_ERR(selene_server_create(conf, &s));
  SLN_ASSERT_CONTEXT(s);

  baton = (sln_native_baton_t *)s->backend_baton;

  for (i = maxlen; i <= maxlen; i++) {
    SLN_ERR(sln_bucket_create_copy_bytes(&e1,
                                         alert_close_notify,
                                         i));
    SLN_BRIGADE_INSERT_TAIL(baton->in_alert, e1);
    err  = sln_native_io_alert_read(s, baton);
    if (err) {
      SLN_ASSERT(err->err == SELENE_EINVAL);
    }
    else {
      /* TODO: more asserts */
    }
    sln_brigade_clear(baton->in_alert);
  }

  selene_destroy(s);
  selene_conf_destroy(conf);
}

static void alert_to_self(void **state)
{
  selene_error_t *err;
  sln_bucket_t *balert = NULL;
  sln_msg_alert_t alert;
  sln_native_baton_t *baton;
  selene_conf_t *conf = NULL;
  selene_t *s = NULL;

  selene_conf_create(&conf);
  SLN_ERR(selene_conf_use_reasonable_defaults(conf));
  SLN_ERR(selene_server_create(conf, &s));
  SLN_ASSERT_CONTEXT(s);

  alert.level = SLN_ALERT_LEVEL_FATAL;
  alert.description = SLN_ALERT_DESC_UNEXPECTED_MESSAGE;

  baton = (sln_native_baton_t *)s->backend_baton;

  err = sln_native_alert_unparse(&alert, &balert);
  SLN_ASSERT(err == SELENE_SUCCESS);
  SLN_BRIGADE_INSERT_TAIL(baton->in_handshake, balert);

  err  = sln_native_io_alert_read(s, baton);

  if (err) {
    SLN_ASSERT(err->err == SELENE_EINVAL);
  }
  else {
    /* TODO: more asserts */
  }

  sln_brigade_clear(baton->in_alert);
  selene_destroy(s);
  selene_conf_destroy(conf);
}

SLN_TESTS_START(alert_io)
  SLN_TESTS_ENTRY(alert_msg)
  SLN_TESTS_ENTRY(alert_to_self)
SLN_TESTS_END()
