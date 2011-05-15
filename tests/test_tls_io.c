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

/**
 * Packet Capture from OpenSSL s_client sending a client hello.
 */
static char openssl_client_hello_basic[] = {
  0x16, 0x03, 0x01, 0x00, 0xce, 0x01, 0x00, 0x00, 
  0xca, 0x03, 0x01, 0x4d, 0xc5, 0xa9, 0x90, 0x4f, 
  0xfe, 0x47, 0x4c, 0xc4, 0x64, 0x34, 0x1b, 0x73, 
  0x8f, 0xb3, 0xd5, 0xbc, 0xc9, 0xde, 0xdf, 0xbc, 
  0xec, 0x76, 0x4d, 0x9e, 0x28, 0x2e, 0x1c, 0xf0, 
  0xf2, 0x60, 0xc7, 0x00, 0x00, 0x5c, 0xc0, 0x14, 
  0xc0, 0x0a, 0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 
  0x00, 0x87, 0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 
  0x00, 0x84, 0xc0, 0x12, 0xc0, 0x08, 0x00, 0x16, 
  0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03, 0x00, 0x0a, 
  0xc0, 0x13, 0xc0, 0x09, 0x00, 0x33, 0x00, 0x32, 
  0x00, 0x9a, 0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 
  0xc0, 0x0e, 0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 
  0x00, 0x41, 0x00, 0x07, 0xc0, 0x11, 0xc0, 0x07, 
  0xc0, 0x0c, 0xc0, 0x02, 0x00, 0x05, 0x00, 0x04, 
  0x00, 0x15, 0x00, 0x12, 0x00, 0x09, 0x00, 0x14, 
  0x00, 0x11, 0x00, 0x08, 0x00, 0x06, 0x00, 0x03, 
  0x00, 0xff, 0x02, 0x01, 0x00, 0x00, 0x44, 0x00, 
  0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 
  0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x01, 0x00, 
  0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 
  0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09, 0x00, 
  0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0d, 0x00, 
  0x0e, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11, 0x00, 
  0x12, 0x00, 0x13, 0x00, 0x14, 0x00, 0x15, 0x00, 
  0x16, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 
  0x23, 0x00, 0x00
};

static void tls_io_slowly(void **state)
{
  selene_error_t *err;
  sln_native_baton_t *baton;
  selene_conf_t *conf = NULL;
  selene_t *s = NULL;
  sln_bucket_t *e1;
  size_t maxlen = sizeof(openssl_client_hello_basic);
  size_t i;

  selene_conf_create(&conf);
  SLN_ERR(selene_conf_use_reasonable_defaults(conf));
  SLN_ERR(selene_server_create(conf, &s));
  SLN_ASSERT_CONTEXT(s);

  baton = (sln_native_baton_t *)s->backend_baton;

  for (i = 0; i <= maxlen; i++) {
    SLN_ERR(sln_bucket_create_copy_bytes(&e1,
                                         openssl_client_hello_basic,
                                         i));
    SLN_BRIGADE_INSERT_TAIL(s->bb.in_enc, e1);
    err  = sln_native_io_tls_read(s, baton);
    if (err) {
      SLN_ASSERT(err->err == SELENE_EINVAL);
    }
    else if (baton->peer_version_major != 0) {
      assert_int_equal(baton->peer_version_major, 3);
      assert_int_equal(baton->peer_version_minor, 1);
    }
    sln_brigade_clear(baton->in_handshake);
    sln_brigade_clear(s->bb.in_enc);
  }

  selene_destroy(s);
  selene_conf_destroy(conf);
}


static const char *http_message = "GET /\r\nHost: example.com\r\n";
typedef struct http_cb_t {
  int gotit;
} http_cb_t;

selene_error_t*
http_cb(selene_t *ctxt, selene_event_e event, void *baton)
{
  http_cb_t *b = (http_cb_t*) baton;
  b->gotit++;
  return SELENE_SUCCESS;
}

static void tls_http_accident(void **state)
{
  selene_error_t *err;
  sln_native_baton_t *baton;
  selene_conf_t *conf = NULL;
  selene_t *s = NULL;
  http_cb_t cbb;
  sln_bucket_t *e1;

  selene_conf_create(&conf);
  SLN_ERR(selene_conf_use_reasonable_defaults(conf));
  SLN_ERR(selene_server_create(conf, &s));
  SLN_ASSERT_CONTEXT(s);

  baton = (sln_native_baton_t *)s->backend_baton;

  cbb.gotit = 0;
  selene_handler_set(s, SELENE_EVENT_TLS_GOT_HTTP, http_cb, &cbb);

  SLN_ERR(sln_bucket_create_copy_bytes(&e1,
                                       http_message,
                                       strlen(http_message)));
  SLN_BRIGADE_INSERT_TAIL(s->bb.in_enc, e1);
  err  = sln_native_io_tls_read(s, baton);
  SLN_ASSERT(err != NULL);
  SLN_ASSERT(err->err == SELENE_EINVAL);
  selene_error_clear(err);
  assert_int_equal(1, cbb.gotit);
  selene_destroy(s);
  selene_conf_destroy(conf);
}

SLN_TESTS_START(tls_io)
  SLN_TESTS_ENTRY(tls_io_slowly)
  SLN_TESTS_ENTRY(tls_http_accident)
SLN_TESTS_END()
