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

#include "sln_brigades.h"
#include "parser.h"
#include "handshake_messages.h"

selene_error_t*
sln_parser_initilize()
{
  return SELENE_SUCCESS;
}

void
sln_parser_terminate()
{
}

selene_error_t*
sln_parser_create(selene_t *s)
{
  sln_parser_baton_t *baton;
  SLN_ASSERT_CONTEXT(s);

  baton = (sln_parser_baton_t*) sln_calloc(s, sizeof(*baton));
  s->backend_baton = baton;
  sln_brigade_create(s->alloc, &baton->in_ccs);
  sln_brigade_create(s->alloc, &baton->in_alert);
  sln_brigade_create(s->alloc, &baton->in_handshake);
  sln_brigade_create(s->alloc, &baton->in_application);

  sln_handshake_register_callbacks(s);

  return SELENE_SUCCESS;
}

static selene_error_t*
have_io(selene_t *s, selene_event_e event, void *baton_)
{
  sln_parser_baton_t *baton;
  SLN_ASSERT_CONTEXT(s);

  baton = s->backend_baton;
  return sln_state_machine(s, baton);
}

selene_error_t*
sln_parser_start(selene_t *s)
{
  sln_parser_baton_t *baton;
  SLN_ASSERT_CONTEXT(s);

  baton = s->backend_baton;

  if (s->mode == SLN_MODE_CLIENT) {
    baton->handshake = SLN_HANDSHAKE_CLIENT_SEND_HELLO;
  }
  else {
    baton->handshake = SLN_HANDSHAKE_SERVER_WAIT_CLIENT_HELLO;
  }

  slnDbg(s, "starting client, handshake state %d", baton->handshake);

  SELENE_ERR(selene_subscribe(s, SELENE_EVENT_IO_IN_ENC, have_io, NULL));
  SELENE_ERR(selene_subscribe(s, SELENE_EVENT_IO_IN_CLEAR, have_io, NULL));

  return sln_state_machine(s, baton);
}

selene_error_t*
sln_parser_destroy(selene_t *s)
{
  sln_parser_baton_t *baton;
  SLN_ASSERT_CONTEXT(s);

  baton = s->backend_baton;

  sln_brigade_destroy(baton->in_ccs);
  sln_brigade_destroy(baton->in_alert);
  sln_brigade_destroy(baton->in_handshake);
  sln_brigade_destroy(baton->in_application);

  sln_free(s, baton);

  s->backend_baton = NULL;

  if (baton->fatal_err) {
    selene_error_clear(baton->fatal_err);
    baton->fatal_err = SELENE_SUCCESS;
  }

  return SELENE_SUCCESS;
}
