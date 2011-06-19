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
  sln_msg_tls_t tls;
  sln_bucket_t *btls = NULL;
  sln_bucket_t *bhs = NULL;

  sln_parser_tls_max_supported_version(s, &ch.version_major, &ch.version_minor);

  ch.utc_unix_time = time(NULL);

  sln_parser_rand_bytes_secure(&ch.random_bytes[0], sizeof(ch.random_bytes));

  ch.session_id_len = 0;
  ch.ciphers = &s->conf->ciphers;
  ch.server_name = NULL;
  ch.have_npn = 0;
  ch.have_ocsp_stapling = 0;
  SELENE_ERR(sln_handshake_unparse_client_hello(s, &ch, &bhs));

  tls.content_type = SLN_CONTENT_TYPE_HANDSHAKE;
  sln_parser_tls_set_current_version(s, &tls.version_major, &tls.version_minor);
  tls.length = bhs->size;

  SELENE_ERR(sln_tls_unparse_header(s, &tls, &btls));

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
      hs->current_msg_finish = sln_handshake_parse_client_hello_finish;
      hs->current_msg_destroy = sln_handshake_parse_client_hello_destroy;
      return sln_handshake_parse_client_hello_setup(hs, v, &hs->current_msg_baton);
      break;
    case SLN_HS_MT_HELLO_REQUEST:
      /* TODO: fatal alert (?) */
      break;
    case SLN_HS_MT_SERVER_HELLO:
      hs->state = SLN_HS_MESSAGE_PARSER;
      hs->current_msg_step = sln_handshake_parse_server_hello_step;
      hs->current_msg_finish = sln_handshake_parse_server_hello_finish;
      hs->current_msg_destroy = sln_handshake_parse_server_hello_destroy;
      return sln_handshake_parse_server_hello_setup(hs, v, &hs->current_msg_baton);
      break;
    case SLN_HS_MT_CERTIFICATE:
      hs->state = SLN_HS_MESSAGE_PARSER;
      hs->current_msg_step = sln_handshake_parse_certificate_step;
      hs->current_msg_finish = sln_handshake_parse_certificate_finish;
      hs->current_msg_destroy = sln_handshake_parse_certificate_destroy;
      return sln_handshake_parse_certificate_setup(hs, v, &hs->current_msg_baton);
      break;
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
      hs->remaining = hs->length;
      err = setup_mt_parser(v, hs);
      hs->remaining -= v->wantlen;
      break;
    case SLN_HS_MESSAGE_PARSER:
      err = hs->current_msg_step(hs, v, hs->current_msg_baton);

      hs->remaining -= v->wantlen;
      //slnDbg(s, "remaining: %d want: %u\n", hs->remaining, v->wantlen);
      if (hs->remaining < 0) {

        if (hs->current_msg_baton != NULL && hs->current_msg_finish != NULL) {
          err = hs->current_msg_finish(hs, hs->current_msg_baton);
        }

        if (hs->current_msg_baton != NULL && hs->current_msg_destroy != NULL) {
          hs->current_msg_destroy(hs, hs->current_msg_baton);
        }

        hs->current_msg_baton = NULL;

        hs->state = SLN_HS_MESSAGE_TYPE;
        v->next = TOK_COPY_BYTES;
        v->wantlen = 1;
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

  hs.s = s;
  hs.baton = baton;
  hs.state = SLN_HS__INIT;
  hs.current_msg_baton = NULL;
  hs.current_msg_step = NULL;
  hs.current_msg_finish = NULL;
  hs.current_msg_destroy = NULL;

  sln_tok_parser(baton->in_handshake, read_handshake_parser, &hs);

  if (hs.current_msg_baton != NULL && hs.current_msg_destroy != NULL) {
    hs.current_msg_destroy(&hs, hs.current_msg_baton);
  }

  return SELENE_SUCCESS;
}

selene_error_t*
sln_handshake_handle_client_hello(selene_t *s, selene_event_e event, void *baton_)
{
  sln_parser_baton_t *baton = s->backend_baton;
  sln_msg_client_hello_t *ch = baton->msg.client_hello;

  if (ch->version_major < SLN_PARSER_VERSION_MAJOR_MIN) {
    /* Disable SSLv2 and 'older' */
    sln_io_alert_fatal(s, SLN_ALERT_DESC_PROTOCOL_VERSION);
    return SELENE_SUCCESS;
  }

  /* TODO: validate other parameters / extensions */

  /* TODO: move to post-finding certificate callback */
  {
    sln_msg_server_hello_t sh;
    sln_msg_tls_t tls;
    sln_bucket_t *btls = NULL;
    sln_bucket_t *bhs = NULL;

    sln_parser_tls_max_supported_version(s, &sh.version_major, &sh.version_minor);
    sh.utc_unix_time = time(NULL);
    sln_parser_rand_bytes_secure(&sh.random_bytes[0], sizeof(sh.random_bytes));
    /* TODO: session ID lookup */
    sh.session_id_len = 0;
    /* TODO: select from client suggested ciphers in the order of our own cipher list. */
    sh.cipher = SELENE_CS_RSA_WITH_RC4_128_SHA;
    SELENE_ERR(sln_handshake_unparse_server_hello(s, &sh, &bhs));

    /* TODO: create certificate message for non-PSK ciphers */
    tls.content_type = SLN_CONTENT_TYPE_HANDSHAKE;
    sln_parser_tls_set_current_version(s, &tls.version_major, &tls.version_minor);
    tls.length = bhs->size;

    SELENE_ERR(sln_tls_unparse_header(s, &tls, &btls));

    SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, btls);

    SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, bhs);
  }
  return SELENE_SUCCESS;
}
