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

#include "parser.h"
#include "sln_tok.h"
#include "alert_messages.h"
#include <string.h>
#include <stdio.h>

typedef enum tls_ct_e {
  /**
   * 0x14 20 ChangeCipherSpec
   * 0x15 21 Alert
   * 0x16 22 Handshake
   * 0x17 23 Application
   */
   TLS_CT_CHANGE_CIPHER_SPEC = 20,
   TLS_CT_ALERT = 21,
   TLS_CT_HANDSHAKE = 22,
   TLS_CT_APPLICATION = 23
} tls_ct_e;

typedef enum tls_record_state_e {
  TLS_RS__UNUSED,
  TLS_RS__INIT,
  TLS_RS_CONTENT_TYPE,
  TLS_RS_VERSION,
  TLS_RS_LENGTH,
  TLS_RS_MESSAGE,
  TLS_RS_MAC,
  TLS_RS_PADDING,
  TLS_RS_MAYBE_HTTP_REQUEST,
  TLS_RS__DONE,
  TLS_RS__MAX
} tls_record_state_e;

typedef struct rtls_baton_t {
  selene_t *s;
  tls_record_state_e state;
  sln_parser_baton_t *baton;
  tls_ct_e content_type;
  uint8_t version_major;
  uint8_t version_minor;
  uint16_t length;
  size_t consume;
} rtls_baton_t;

static int
is_valid_content_type(uint8_t input) {
  if (input == TLS_CT_CHANGE_CIPHER_SPEC ||
      input == TLS_CT_ALERT ||
      input == TLS_CT_HANDSHAKE ||
      input == TLS_CT_APPLICATION) {
    return 1;
  }
  return 0;
}

static selene_error_t*
read_tls(sln_tok_value_t *v, void *baton_)
{
  rtls_baton_t *rtls = (rtls_baton_t*)baton_;
  sln_parser_baton_t *baton = rtls->baton;

  switch (rtls->state) {
    case TLS_RS__INIT:
      /* get our first byte for the TLS_RS_CONTENT_TYPE */
      rtls->state = TLS_RS_CONTENT_TYPE;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 1;
      break;
    case TLS_RS_MAYBE_HTTP_REQUEST:
      /* TODO: send alert breaking connection */
      if ((rtls->content_type == 'G' && memcmp(&v->v.bytes[0], "ET ", 3) == 0) ||
          (rtls->content_type == 'P' && memcmp(&v->v.bytes[0], "OST", 3) == 0)) {
        selene_publish(rtls->s, SELENE_EVENT_TLS_GOT_HTTP);
        return selene_error_create(SELENE_EINVAL, "Got possible HTTP request instead of TLS?");
      }
      else {
        return selene_error_createf(SELENE_EINVAL, "Invalid content type: %u", rtls->content_type);
      }
      break;
    case TLS_RS_CONTENT_TYPE:
      rtls->content_type = v->v.bytes[0];
      rtls->consume += 1;
      if (!is_valid_content_type(rtls->content_type)) {
        /* TODO: accept this ONLY for the very first TLS message we recieve */
        if (baton->got_first_packet == 0 && (rtls->content_type == 'G' || rtls->content_type == 'P')) {
          rtls->state = TLS_RS_MAYBE_HTTP_REQUEST;
          v->next = TOK_COPY_BYTES;
          v->wantlen = 3;
          break;
        }
        else {
          /* TODO: send alert breaking connection */
          return selene_error_createf(SELENE_EINVAL, "Invalid content type: %u", rtls->content_type);
        }
      }
      baton->got_first_packet = 1;
      rtls->state = TLS_RS_VERSION;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 2;
      break;
    case TLS_RS_VERSION:
      rtls->version_major = v->v.bytes[0];
      rtls->version_minor = v->v.bytes[1];
      rtls->consume += 2;
      rtls->state = TLS_RS_LENGTH;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 2;
      break;
    case TLS_RS_LENGTH:
      rtls->length = (((unsigned char)v->v.bytes[0]) << 8 |  ((unsigned char)v->v.bytes[1]));
      rtls->state = TLS_RS_MESSAGE;
      rtls->consume += 2;
      v->next = TOK_COPY_BRIGADE;
      v->wantlen = rtls->length;
      break;
    case TLS_RS_MESSAGE:
      /* TODO: efficient slicing of brigades instead of copying data here */
      rtls->consume += sln_brigade_size(v->v.bb);
      switch (rtls->content_type) {
        case TLS_CT_CHANGE_CIPHER_SPEC:
          SLN_BRIGADE_CONCAT(baton->in_ccs, v->v.bb);
          break;
        case TLS_CT_ALERT:
          SLN_BRIGADE_CONCAT(baton->in_alert, v->v.bb);
          break;
        case TLS_CT_HANDSHAKE:
          SLN_BRIGADE_CONCAT(baton->in_handshake, v->v.bb);
          break;
        case TLS_CT_APPLICATION:
          SLN_BRIGADE_CONCAT(baton->in_application, v->v.bb);
          break;
        default:
          /* TODO: send alert breaking connection */
          break;
      }
      rtls->state = TLS_RS__DONE;
      v->next = TOK_DONE;
      v->wantlen = 0;
      /* TODO: MAC / padding */
      break;
    default:
      /* TODO: error handling */
      abort();
      break;
  }

  return SELENE_SUCCESS;
}

selene_error_t*
sln_io_tls_read(selene_t *s, sln_parser_baton_t *baton)
{
  rtls_baton_t rtls;
  selene_error_t* err;

  do {
    slnDbg(s, "tls read pending: %d", (int)sln_brigade_size(s->bb.in_enc));
    memset(&rtls, 0, sizeof(rtls));
    rtls.s = s;
    rtls.baton = baton;
    rtls.state = TLS_RS__INIT;

    err = sln_tok_parser(s->bb.in_enc, read_tls, &rtls);

    if (err) {
      /* TODO: logging here? */
      sln_io_alert_fatal(s, SLN_ALERT_DESC_INTERNAL_ERROR);
      return err;
    }

    if (rtls.state == TLS_RS__DONE) {
      /* Consumed a whole TLS packet, otherwise we got part way done */
      sln_brigade_chomp(s->bb.in_enc, rtls.consume);
      slnDbg(s, "tls read chomping: %d", (int)rtls.consume);

      /* TODO: only on first packet (?)  SSLv2 Hello?? */
      baton->peer_version_major = rtls.version_major;
      baton->peer_version_minor = rtls.version_minor;
    }
  } while (err == SELENE_SUCCESS &&
           rtls.state == TLS_RS__DONE &&
           !SLN_BRIGADE_EMPTY(s->bb.in_enc));

  return SELENE_SUCCESS;
}


selene_error_t*
sln_tls_params_update_mac(selene_t *s, sln_params_t *p, sln_bucket_t *b)
{

  switch (p->suite) {
    /* TODO: impl */
    case SELENE_CS__UNUSED0:
    case SELENE_CS__MAX:
    case SELENE_CS_RSA_WITH_RC4_128_SHA:
    case SELENE_CS_RSA_WITH_AES_128_CBC_SHA:
    case SELENE_CS_RSA_WITH_AES_256_CBC_SHA:
      break;
  }

  return SELENE_SUCCESS;
}

selene_error_t*
sln_tls_params_encrypt(selene_t *s, sln_params_t *p, sln_bucket_t *b, sln_bucket_t **out)
{
  *out = NULL;

  switch (p->suite) {
    /* TODO: impl */
    case SELENE_CS__UNUSED0:
    case SELENE_CS__MAX:
    case SELENE_CS_RSA_WITH_RC4_128_SHA:
    case SELENE_CS_RSA_WITH_AES_128_CBC_SHA:
    case SELENE_CS_RSA_WITH_AES_256_CBC_SHA:
      break;
  }

  return SELENE_SUCCESS;
}

