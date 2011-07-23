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

typedef struct s_baton_t {
  selene_t *s;
  selene_t *sendto;
} s_baton_t;

static selene_error_t*
want_pull(selene_t *s, selene_event_e event, void *baton)
{
  char buf[8096];
  size_t blen = 0;
  size_t remaining = 0;
  s_baton_t *c = (s_baton_t*) baton;

  do {
    SLN_ERR(selene_io_out_enc_bytes(s,
                                 &buf[0], sizeof(buf),
                                 &blen, &remaining));
    if (blen > 0) {
      SLN_ERR(selene_io_in_enc_bytes(c->sendto, buf, blen));
    }
  } while(remaining > 0);

  return SELENE_SUCCESS;
}

static selene_error_t*
have_cleartext(selene_t *s, selene_event_e event, void *baton)
{
  char buf[8096];
  size_t blen = 0;
  size_t remaining = 0;

  do {
    SLN_ERR(selene_io_out_clear_bytes(s,
                                 &buf[0], sizeof(buf),
                                 &blen, &remaining));

    if (blen > 0) {
      fwrite(buf, blen, 1, stdout);
      fflush(stdout);
    }
  } while(remaining > 0);

  return SELENE_SUCCESS;
}

static void loopback_basic(void **state)
{
  selene_conf_t *conf = NULL;
  selene_t *server = NULL;
  s_baton_t serverb;
  selene_t *client = NULL;
  s_baton_t clientb;


  selene_conf_create(&conf);

  SLN_ERR(selene_conf_use_reasonable_defaults(conf));
  SLN_ERR(selene_server_create(conf, &server));
  SLN_ASSERT_CONTEXT(server);

  SLN_ERR(selene_conf_use_reasonable_defaults(conf));
  SLN_ERR(selene_client_create(conf, &client));
  SLN_ASSERT_CONTEXT(client);

  serverb.s = server;
  serverb.sendto = client;
  clientb.s = client;
  clientb.sendto = server;

  SLN_ERR(selene_client_name_indication(client, "localhost"));

  SLN_ERR(selene_client_next_protocol_add(client, "http/1.1"));


  SLN_ERR(selene_subscribe(server, SELENE_EVENT_IO_OUT_ENC,
                        want_pull, &serverb));
  SLN_ERR(selene_subscribe(server, SELENE_EVENT_IO_OUT_CLEAR,
                        have_cleartext, &serverb));


  SLN_ERR(selene_subscribe(client, SELENE_EVENT_IO_OUT_ENC,
                        want_pull, &clientb));
  SLN_ERR(selene_subscribe(client, SELENE_EVENT_IO_OUT_CLEAR,
                        have_cleartext, &clientb));

  SLN_ERR(selene_start(server));
  SLN_ERR(selene_start(client));

}

SLN_TESTS_START(loopback)
  SLN_TESTS_ENTRY(loopback_basic)
SLN_TESTS_END()
