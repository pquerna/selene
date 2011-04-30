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

#include "native.h"
#include "sln_tok.h"

typedef enum tls_record_state_e {
  TLS_RS__UNUSED,
  TLS_RS_CONTENT_TYPE,
  TLS_RS_VERSION,
  TLS_RS_LENGTH,
  TLS_RS_MESSAGE,
  TLS_RS_MAC,
  TLS_RS_PADDING,
  TLS_RS__MAX,
} tls_record_state_e;

typedef struct rtls_baton_t {
  selene_t *s;
  tls_record_state_e state;
  sln_native_baton_t *baton;
} rtls_baton_t;

static selene_error_t*
read_tls(sln_tok_value_t *v, void *baton_)
{
  rtls_baton_t *rtls = (rtls_baton_t*)baton_;
  sln_native_baton_t *baton = rtls->baton;

  if (rtls->state == TLS_RS__UNUSED) {
    /* get our first byte for the TLS_RS_CONTENT_TYPE */
    rtls->state = TLS_RS_CONTENT_TYPE;
    v->next = TOK_SINGLE_BYTE;
    return SELENE_SUCCESS;
  }

  switch (rtls->state) {
    case TLS_RS_CONTENT_TYPE:
      if (v->current != TOK_SINGLE_BYTE) {
        abort();
      }

      break;
    case TLS_RS_MESSAGE:
      if (v->current != TOK_SLICE_BRIGADE) {
        abort();
      }

      SLN_BRIGADE_CONCAT(baton->in_handshake, v->v.bb);
      break;
    default:
      /* TODO: error handling */
      abort();
      break;
  }

  return SELENE_SUCCESS;
}

selene_error_t*
sln_native_io_tls_read(selene_t *s, sln_native_baton_t *baton)
{
  rtls_baton_t rtls;
  selene_error_t* err;

  rtls.s = s;
  rtls.baton = baton;
  rtls.state = TLS_RS__UNUSED;

  err = sln_tok_parser(s->bb.in_enc, read_tls, &rtls);

  if (err) {
    /* TODO: invalidate connection? */
    return err;
  }

  return SELENE_SUCCESS;
}
