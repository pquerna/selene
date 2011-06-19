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

#include "../parser.h"
#include "../handshake_messages.h"
#include <string.h>

selene_error_t*
sln_handshake_unparse_certificate(selene_t *s, sln_msg_certificate_t *cert, sln_bucket_t **p_b)
{
  /* TODO: impl */
  return SELENE_SUCCESS;
}


typedef struct cert_baton_t {
  sln_handshake_certificate_state_e state;
  sln_msg_certificate_t cert;
} cert_baton_t;

selene_error_t*
sln_handshake_parse_certificate_setup(sln_hs_baton_t *hs, sln_tok_value_t *v, void **baton)
{
  cert_baton_t *certb = sln_calloc(hs->s, sizeof(cert_baton_t));
  certb->state = SLN_HS_CERTIFICATE_LENGTH;
  hs->baton->msg.certificate = &certb->cert;
  v->next = TOK_COPY_BYTES;
  v->wantlen = 3;
  *baton = (void*)certb;
  return SELENE_SUCCESS;
}

selene_error_t*
sln_handshake_parse_certificate_step(sln_hs_baton_t *hs, sln_tok_value_t *v, void *baton)
{
  cert_baton_t *certb = (cert_baton_t*)baton;
  sln_msg_certificate_t *cert = &certb->cert;
  selene_t *s = hs->s;

  switch (certb->state) {
    /* TODO: impl */
    default:
      break;
  }

  return SELENE_SUCCESS;
}

selene_error_t*
sln_handshake_parse_certificate_finish(sln_hs_baton_t *hs, void *baton)
{
  return selene_publish(hs->s, SELENE__EVENT_HS_GOT_CERTIFICATE);
}

void
sln_handshake_parse_certificate_destroy(sln_hs_baton_t *hs, void *baton)
{
  cert_baton_t *certb = (cert_baton_t*)baton;

  sln_free(hs->s, certb);
}
