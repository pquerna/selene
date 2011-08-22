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
#include "parser.h"
#include "handshake_messages.h"
#include "common.h"

#include <time.h>
#include <string.h>

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
sln_io_handshake_client_hello(selene_t *s, sln_parser_baton_t *baton)
{
  sln_msg_client_hello_t ch;
  sln_bucket_t *bhs = NULL;

  sln_parser_tls_max_supported_version(s, &ch.version_major, &ch.version_minor);

  ch.utc_unix_time = time(NULL);

  sln_parser_rand_bytes_secure(&ch.random_bytes[0], sizeof(ch.random_bytes));

  ch.session_id_len = 0;
  ch.ciphers = &s->conf->ciphers;
  ch.server_name = (char*)s->client_sni;
  ch.have_npn = 0;
  ch.have_ocsp_stapling = 0;
  SELENE_ERR(sln_handshake_serialize_client_hello(s, &ch, &bhs));

  SELENE_ERR(sln_tls_toss_bucket(s, SLN_CONTENT_TYPE_HANDSHAKE, bhs));

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
  selene_t *s = hs->s;

  slnDbg(s, "GOT MESSAGE TYPE SETUP: %d", hs->message_type);

  switch (hs->message_type) {
    case SLN_HS_MT_CLIENT_HELLO:
      hs->state = SLN_HS_MESSAGE_PARSER;
      return sln_handshake_parse_client_hello_setup(hs, v, &hs->current_msg_baton);
      break;
    case SLN_HS_MT_HELLO_REQUEST:
      /* TODO: fatal alert (?) */
      break;
    case SLN_HS_MT_SERVER_HELLO:
      slnDbg(s, "parsing server hello..");
      hs->state = SLN_HS_MESSAGE_PARSER;
      return sln_handshake_parse_server_hello_setup(hs, v, &hs->current_msg_baton);
      break;
    case SLN_HS_MT_CERTIFICATE:
      slnDbg(s, "parsing the certificate...");
      hs->state = SLN_HS_MESSAGE_PARSER;
      return sln_handshake_parse_certificate_setup(hs, v, &hs->current_msg_baton);
      break;
    case SLN_HS_MT_SERVER_HELLO_DONE:
      slnDbg(s, "parsing server hello done...");
      hs->state = SLN_HS_MESSAGE_PARSER;
      return sln_handshake_parse_server_hello_done_setup(hs, v, &hs->current_msg_baton);
      break;
    case SLN_HS_MT_SERVER_KEY_EXCHANGE:
    case SLN_HS_MT_CERTIFICATE_REQUEST:
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
  selene_t *s = hs->s;

  slnDbg(s, "IN HANDSHAKE PARSER, STATE: %d", hs->state);

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
        hs->current_msg_consume += 1;
        hs->state = SLN_HS_LENGTH;
        v->next = TOK_UINT24;
        v->wantlen = 3;
      }
      break;
    case SLN_HS_LENGTH:
      hs->length = v->v.uint24;
      hs->current_msg_consume += 3 + hs->length;
      hs->remaining = hs->length;
      err = setup_mt_parser(v, hs);
      hs->remaining -= v->wantlen;
      break;
    case SLN_HS_MESSAGE_PARSER:
      err = hs->current_msg_step(hs, v, hs->current_msg_baton);

      hs->remaining -= v->wantlen;
      /* slnDbg(s, "remaining: %d want: %u\n", hs->remaining, v->wantlen); */
      if (hs->remaining < 0) {

        if (hs->current_msg_baton != NULL && hs->current_msg_finish != NULL) {
          err = hs->current_msg_finish(hs, hs->current_msg_baton);
        }

        if (hs->current_msg_baton != NULL && hs->current_msg_destroy != NULL) {
          hs->current_msg_destroy(hs, hs->current_msg_baton);
        }

        hs->current_msg_baton = NULL;

        hs->state = SLN_HS__DONE;
        v->next = TOK_DONE;
        v->wantlen = 0;
      }
      break;
    default:
      hs->state = SLN_HS__DONE;
      v->next = TOK_DONE;
      v->wantlen = 0;
  }
  return err;
}

selene_error_t*
sln_io_handshake_read(selene_t *s, sln_parser_baton_t *baton)
{
  sln_hs_baton_t hs;
  selene_error_t *err = SELENE_SUCCESS;
  do {
    hs.s = s;
    hs.baton = baton;
    hs.state = SLN_HS__INIT;
    hs.current_msg_baton = NULL;
    hs.current_msg_step = NULL;
    hs.current_msg_finish = NULL;
    hs.current_msg_destroy = NULL;
    hs.current_msg_consume = 0;

    err = sln_tok_parser(baton->in_handshake, read_handshake_parser, &hs);

    if (hs.current_msg_baton != NULL && hs.current_msg_destroy != NULL) {
      hs.current_msg_destroy(&hs, hs.current_msg_baton);
    }

    if (hs.state == SLN_HS__DONE) {
      slnDbg(s, "handshake chomping: %d", (int)hs.current_msg_consume);
      sln_brigade_chomp(baton->in_handshake, hs.current_msg_consume);
    }
  } while (err == SELENE_SUCCESS &&
           hs.state == SLN_HS__DONE &&
           !SLN_BRIGADE_EMPTY(baton->in_handshake));

  return err;
}
