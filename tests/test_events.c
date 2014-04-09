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

typedef struct baton_t {
  selene_event_e etype;
  int count;
} baton_t;

static selene_error_t *event_cb(selene_t *ctxt, selene_event_e event,
                                void *baton_) {
  baton_t *baton = (baton_t *)baton_;
  assert_int_equal(event, baton->etype);
  baton->count++;
  return SELENE_SUCCESS;
}

static void event_handlers(void **state) {
  selene_conf_t *conf = NULL;
  selene_t *ctxt = NULL;
  selene_event_e e = SELENE_EVENT_IOWANT_CHANGED;
  baton_t b1;
  baton_t b2;

  selene_conf_create(&conf);
  SLN_ERR(selene_client_create(conf, &ctxt));
  SLN_ASSERT_CONTEXT(ctxt);

  b1.count = 0;
  b1.etype = e;

  b2.count = 0;
  b2.etype = e;

  SLN_ERR(selene_handler_set(ctxt, e, event_cb, &b1));
  SLN_ERR(selene_subscribe(ctxt, e, event_cb, &b1));
  SLN_ERR(selene_subscribe(ctxt, e, event_cb, &b2));
  SLN_ERR(selene_publish(ctxt, e));

  assert_int_equal(2, b1.count);
  assert_int_equal(1, b2.count);

  SLN_ERR(selene_unsubscribe(ctxt, e, event_cb, &b1));
  SLN_ERR(selene_publish(ctxt, e));

  assert_int_equal(3, b1.count);
  assert_int_equal(2, b2.count);

  SLN_ERR(selene_unsubscribe(ctxt, e, NULL, &b1));

  selene_destroy(ctxt);
  selene_conf_destroy(conf);
}

SLN_TESTS_START(events)
SLN_TESTS_ENTRY(event_handlers)
SLN_TESTS_END()
