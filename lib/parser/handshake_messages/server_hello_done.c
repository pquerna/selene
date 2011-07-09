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
sln_handshake_serialize_server_hello_done(selene_t *s, sln_msg_server_hello_done_t *sh, sln_bucket_t **p_b)
{
  sln_bucket_t *b = NULL;
  size_t len = 0;
  size_t off = 0;

  /* message type  size */
  len += 1;

  /* length size */
  len += 3;

  sln_bucket_create_empty(s->alloc, &b, len);

  b->data[off] = SLN_HS_MT_SERVER_HELLO_DONE;
  off += 1;

  b->data[off] = 0;
  b->data[off+1] = 0;
  b->data[off+2] = 0;
  off += 3;

  assert(off == len);

  *p_b = b;

  return SELENE_SUCCESS;
}


typedef struct shd_baton_t {
  sln_handshake_server_hello_done_state_e state;
  sln_msg_server_hello_done_t shd;
} shd_baton_t;

static selene_error_t*
parse_server_hello_done_step(sln_hs_baton_t *hs, sln_tok_value_t *v, void *baton)
{
  shd_baton_t *shb = (shd_baton_t*)baton;

  switch (shb->state) {
    case SLN_HS_SERVER_HELLO_DONE_LENGTH:
    {
      /* TODO: validite zero bytes in length? */
      v->next = TOK_DONE;
      v->wantlen = 0;
      break;
    }
  }

  return SELENE_SUCCESS;
}

static selene_error_t*
parse_server_hello_done_finish(sln_hs_baton_t *hs, void *baton)
{
  return selene_publish(hs->s, SELENE__EVENT_HS_GOT_SERVER_HELLO_DONE);
}

static void
parse_server_hello_done_destroy(sln_hs_baton_t *hs, void *baton)
{
  shd_baton_t *shd = (shd_baton_t*)baton;

  sln_free(hs->s, shd);
}

selene_error_t*
sln_handshake_parse_server_hello_done_setup(sln_hs_baton_t *hs, sln_tok_value_t *v, void **baton)
{
  shd_baton_t *shd = sln_calloc(hs->s, sizeof(shd_baton_t));
  shd->state = SLN_HS_SERVER_HELLO_DONE_LENGTH;
  hs->baton->msg.server_hello_done = &shd->shd;
  hs->current_msg_step = parse_server_hello_done_step;
  hs->current_msg_finish = parse_server_hello_done_finish;
  hs->current_msg_destroy = parse_server_hello_done_destroy;
  v->next = TOK_COPY_BYTES;
  v->wantlen = 3;
  *baton = (void*)shd;
  return SELENE_SUCCESS;
}
