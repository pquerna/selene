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
sln_handshake_serialize_client_key_exchange(selene_t *s, sln_msg_client_key_exchange_t *cke, sln_bucket_t **p_b)
{
  sln_bucket_t *b = NULL;
  size_t len = 0;
  size_t dlen = 0;
  size_t off = 0;

  /* message type  size */
  len += 1;

  /* length size */
  len += 3;

  /* pre master key size */
  len += 2;
  len += cke->pre_master_secret_length;

  sln_bucket_create_empty(s->alloc, &b, len);

  dlen = len - 4;

  b->data[0] = SLN_HS_MT_CLIENT_KEY_EXCHANGE;
  b->data[1] = dlen >> 16;
  b->data[2] = dlen >> 8;
  b->data[3] = dlen;
  off = 4;

  b->data[off] = cke->pre_master_secret_length >> 8;
  b->data[off+1] = cke->pre_master_secret_length;
  off += 2;

  memcpy(b->data + off, cke->pre_master_secret, cke->pre_master_secret_length);
  off += cke->pre_master_secret_length;

  SLN_ASSERT(off == len);

  *p_b = b;

  return SELENE_SUCCESS;
}

typedef struct cke_baton_t {
  sln_handshake_client_key_exchange_state_e state;
  sln_msg_client_key_exchange_t cke;
} cke_baton_t;

static selene_error_t*
parse_client_key_exchange_step(sln_hs_baton_t *hs, sln_tok_value_t *v, void *baton)
{
  cke_baton_t *ckb = (cke_baton_t*)baton;

  switch (ckb->state) {
    case SLN_HS_CLIENT_KEY_EXCHANGE_LENGTH:
    {
      ckb->cke.pre_master_secret_length = v->v.uint24;
      ckb->state = SLN_HS_CLIENT_KEY_EXCHANGE_DATA;
      v->next = TOK_COPY_BRIGADE;
      v->wantlen = ckb->cke.pre_master_secret_length;
      break;
    }
    case SLN_HS_CLIENT_KEY_EXCHANGE_DATA:
    {
      size_t len = ckb->cke.pre_master_secret_length;
      ckb->cke.pre_master_secret = sln_alloc(hs->s, sln_brigade_size(v->v.bb));
      sln_brigade_flatten(v->v.bb, ckb->cke.pre_master_secret, &len);
      SLN_ASSERT(ckb->cke.pre_master_secret_length == len);
      v->next = TOK_DONE;
      v->wantlen = 0;
      break;
    }
  }

  return SELENE_SUCCESS;
}

static selene_error_t*
parse_client_key_exchange_finish(sln_hs_baton_t *hs, void *baton)
{
  return selene_publish(hs->s, SELENE__EVENT_HS_GOT_CLIENT_KEY_EXCHANGE);
}

static void
parse_client_key_exchange_destroy(sln_hs_baton_t *hs, void *baton)
{
  cke_baton_t *ckb = (cke_baton_t*)baton;

  sln_free(hs->s, ckb);
}

selene_error_t*
sln_handshake_parse_client_key_exchange_setup(sln_hs_baton_t *hs, sln_tok_value_t *v, void **baton)
{
  cke_baton_t *ckb = sln_calloc(hs->s, sizeof(cke_baton_t));
  ckb->state = SLN_HS_CLIENT_KEY_EXCHANGE_LENGTH;
  hs->baton->msg.client_key_exchange = &ckb->cke;
  hs->current_msg_step = parse_client_key_exchange_step;
  hs->current_msg_finish = parse_client_key_exchange_finish;
  hs->current_msg_destroy = parse_client_key_exchange_destroy;
  v->next = TOK_UINT24;
  v->wantlen = 3;
  *baton = (void*)ckb;
  return SELENE_SUCCESS;
}
