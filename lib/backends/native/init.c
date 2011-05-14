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
#include "native.h"


selene_error_t*
sln_native_initilize()
{
  return SELENE_SUCCESS;
}

void
sln_native_terminate()
{
}

selene_error_t*
sln_native_create(selene_t *s)
{
  sln_native_baton_t *baton;
  SLN_ASSERT_CONTEXT(s);

  baton = (sln_native_baton_t*) calloc(1, sizeof(*baton));
  s->backend_baton = baton;
  sln_brigade_create(&baton->in_ccs);
  sln_brigade_create(&baton->in_alert);
  sln_brigade_create(&baton->in_handshake);
  sln_brigade_create(&baton->in_application);

  return SELENE_SUCCESS;
}

selene_error_t*
sln_native_start(selene_t *s)
{
  sln_native_baton_t *baton;
  SLN_ASSERT_CONTEXT(s);

  baton = s->backend_baton;

  if (s->mode == SLN_MODE_CLIENT) {
    baton->handshake = SLN_NATIVE_HANDSHAKE_CLIENT_SEND_HELLO;
  }
  else {
    baton->handshake = SLN_NATIVE_HANDSHAKE_SERVER_WAIT_CLIENT_HELLO;
  }

  slnDbg(s, "starting native client, handshake state %d", baton->handshake);

  return sln_native_state_machine(s, baton);
}

selene_error_t*
sln_native_destroy(selene_t *s)
{

  return SELENE_SUCCESS;
}
