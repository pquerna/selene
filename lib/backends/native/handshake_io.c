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
#include "sln_tok.h"
#include "native.h"
#include "handshake_messages.h"

#include <time.h>
#include <string.h>

#include <openssl/rand.h>

/* RFC 4346, Section 7.4. Handshake Protocol
 *
 * enum {
 *          hello_request(0), client_hello(1), server_hello(2),
 *          certificate(11), server_key_exchange (12),
 *          certificate_request(13), server_hello_done(14),
 *          certificate_verify(15), client_key_exchange(16),
 *          finished(20), (255)
 *      } HandshakeType;
 */

selene_error_t*
sln_native_io_handshake_client_hello(selene_t *s, sln_native_baton_t *baton)
{
  sln_native_msg_client_hello_t ch;
  sln_native_msg_tls_t tls;
  sln_bucket_t *btls = NULL;
  sln_bucket_t *bhs = NULL;

  ch.version_major = 3;
  ch.version_minor = 1;
  ch.utc_unix_time = time(NULL);

  /* TODO: make sln method for this */
  RAND_bytes((unsigned char *)&ch.random_bytes[0], sizeof(ch.random_bytes));
//  memset(&ch.random_bytes[0], 0xFF, sizeof(ch.random_bytes));

  ch.session_id_len = 0;
  ch.ciphers = &s->conf->ciphers;
  ch.server_name = NULL;
  ch.have_npn = 0;
  ch.have_ocsp_stapling = 0;
  SELENE_ERR(sln_handshake_unparse_client_hello(&ch, &bhs));

  tls.content_type = SLN_NATIVE_CONTENT_TYPE_HANDSHAKE;
  tls.version_major = 3;
  tls.version_minor = 1;
  tls.length = bhs->size;

  SELENE_ERR(sln_tls_unparse_header(&tls, &btls));


  SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, btls);

  SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, bhs);

  return SELENE_SUCCESS;
}


static int
is_valid_message_type(uint8_t input) {
  if (input == SLN_HS_MT_HELLO_REQUEST ||
      input == SLN_HS_MT_CLIENT_HELLO ||
      input == SLN_HS_MT_SERVER_HELLO ||
      input == SLN_HS_MT_CERTIFICATE ||
      input == SLN_HS_MT_SERVER_KEY_EXCHANGE ||
      input == SLN_HS_MT_CERTIFICATE_REQUEST ||
      input == SLN_HS_MT_SERVER_HELLO_DONE ||
      input == SLN_HS_MT_CERTIFICATE_VERIFY ||
      input == SLN_HS_MT_CLIENT_KEY_EXCHANGE ||
      input == SLN_HS_MT_FINISHED) {
    return 1;
  }
  return 0;
}

static selene_error_t*
setup_mt_parser(sln_tok_value_t *v, sln_hs_baton_t *hs)
{
  switch (hs->message_type) {
    case SLN_HS_MT_CLIENT_HELLO:
      hs->state = SLN_HS_MESSAGE_PARSER;
      hs->current_msg_step = sln_handshake_parse_client_hello_step;
      hs->current_msg_destroy = sln_handshake_parse_client_hello_destroy;
      return sln_handshake_parse_client_hello_setup(hs, v, &hs->current_msg_baton);
      break;
    case SLN_HS_MT_HELLO_REQUEST:
    case SLN_HS_MT_SERVER_HELLO:
    case SLN_HS_MT_CERTIFICATE:
    case SLN_HS_MT_SERVER_KEY_EXCHANGE:
    case SLN_HS_MT_CERTIFICATE_REQUEST:
    case SLN_HS_MT_SERVER_HELLO_DONE:
    case SLN_HS_MT_CERTIFICATE_VERIFY:
    case SLN_HS_MT_CLIENT_KEY_EXCHANGE:
    case SLN_HS_MT_FINISHED:
    default:
      hs->state = SLN_HS__DONE;
      v->next = TOK_DONE;
      v->wantlen = 0;
      break;
  }
  return SELENE_SUCCESS;
}

static selene_error_t*
read_handshake_parser(sln_tok_value_t *v, void *baton_)
{
  selene_error_t* err = SELENE_SUCCESS;
  sln_hs_baton_t *hs = (sln_hs_baton_t*)baton_;

  switch (hs->state) {
    case SLN_HS__INIT:
      hs->state = SLN_HS_MESSAGE_TYPE;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 1;
      break;
    case SLN_HS_MESSAGE_TYPE:
      hs->message_type = v->v.bytes[0];
      if (!is_valid_message_type(hs->message_type)) {
        err = selene_error_createf(SELENE_EINVAL, "Invalid handshake message type: %u", hs->message_type);
      }
      else {
        hs->state = SLN_HS_LENGTH;
        v->next = TOK_COPY_BYTES;
        v->wantlen = 3;
      }
      break;
    case SLN_HS_LENGTH:
      hs->length = (((unsigned char)v->v.bytes[0]) << 16 | ((unsigned char)v->v.bytes[1]) << 8 |  ((unsigned char)v->v.bytes[2]));
      err = setup_mt_parser(v, hs);
      break;
    case SLN_HS_MESSAGE_PARSER:
      err = hs->current_msg_step(hs, v, hs->current_msg_baton);
      break;
    default:
      hs->state = SLN_HS__DONE;
      v->next = TOK_DONE;
      v->wantlen = 0;
  }
  return err;
}

selene_error_t*
sln_native_io_handshake_read(selene_t *s, sln_native_baton_t *baton)
{
  sln_hs_baton_t hs;

  hs.s = s;
  hs.baton = baton;
  hs.state = SLN_HS__INIT;
  hs.current_msg_baton = NULL;
  hs.current_msg_step = NULL;
  hs.current_msg_destroy = NULL;

  sln_tok_parser(baton->in_handshake, read_handshake_parser, &hs);

  if (hs.current_msg_baton != NULL && hs.current_msg_destroy != NULL) {
    hs.current_msg_destroy(&hs, hs.current_msg_baton);
  }

  return SELENE_SUCCESS;
}
