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
#include "sln_types.h"
#include "sln_brigades.h"
#include "sln_events.h"
#include "sln_backends.h"
#include "sln_assert.h"
#include "sln_certs.h"

static int initialized = 0;

static selene_error_t*
sln_initialize(void)
{
  /* TODO: Atomics ? */
  if (initialized++) {
    return SELENE_SUCCESS;
  }

  /* TODO: Backend initilization */
  SELENE_ERR(sln_backend_initialize());

  return SELENE_SUCCESS;
}

static void
sln_terminate(void)
{
  initialized--;
  if (initialized) {
    return;
  }

  sln_backend_terminate();

  return;
}

static selene_error_t*
sln_create(selene_conf_t *conf, sln_mode_e mode, selene_t **p_sel)
{
  selene_t *s;

  SELENE_ERR(sln_initialize());

  s = conf->alloc->calloc(conf->alloc->baton, sizeof(selene_t));
  s->alloc = conf->alloc;
  s->conf = conf;
  s->mode = mode;
  s->state = SLN_STATE_INIT;

  s->log_level = SLN_LOG_EVERYTHING;
  s->log_msg = NULL;
  s->log_msg_len = 0;
  s->log_msg_level = SLN_LOG_NOTHING;

  /* TODO: leaks on errors here */
  SELENE_ERR(sln_iobb_create(s->alloc, &s->bb));

  SELENE_ERR(sln_events_create(s));

  /* TODO: make this runtime configurable, add flags (?) */
  SELENE_ERR(sln_backend_create(s, SLN_BACKEND_NATIVE));

  SELENE_ERR(s->backend.create(s));

  SLN_ASSERT_CONTEXT(s);

  *p_sel = s;

  return SELENE_SUCCESS;
}

selene_error_t*
selene_client_create(selene_conf_t *conf, selene_t **p_sel)
{
  return sln_create(conf, SLN_MODE_CLIENT, p_sel);
}

selene_error_t*
selene_server_create(selene_conf_t *conf, selene_t **p_sel)
{
  return sln_create(conf, SLN_MODE_SERVER, p_sel);
}

void 
selene_destroy(selene_t *s)
{
  s->state = SLN_STATE_DEAD;

  sln_iobb_destroy(&s->bb);

  sln_events_destroy(s);

  s->backend.destroy(s);

  if (s->client_sni != NULL) {
    sln_free(s, (void*)s->client_sni);
    s->client_sni = NULL;
  }

  if (s->peer_certs != NULL) {
    sln_cert_chain_destroy(s->conf, s->peer_certs);
    s->peer_certs = NULL;
  }

  if (s->peer_pubkey != NULL) {
    sln_free(s, s->peer_pubkey);
  }

  sln_free(s, s);

  sln_terminate();

}


selene_error_t*
selene_start(selene_t *s)
{
  return s->backend.start(s);
}
