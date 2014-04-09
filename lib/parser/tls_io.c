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
#include "sln_prf.h"
#include "sln_hmac.h"
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

static void get_suite_info(selene_cipher_suite_e suite,
                           size_t *maclen,
                           size_t *keylen,
                           size_t *ivlen)
{
  switch (suite) {
    case SELENE_CS_RSA_WITH_RC4_128_SHA:
      *maclen = 20;
      *keylen = SLN_CIPHER_RC4_128_KEY_LENGTH;
      *ivlen = 0;
      break;
    case SELENE_CS_RSA_WITH_AES_128_CBC_SHA:
      *maclen = 20;
      *keylen = 16;
      *ivlen = 0;
      break;
    case SELENE_CS_RSA_WITH_AES_256_CBC_SHA:
      *maclen = 20;
      *keylen = 32;
      *ivlen = 0;
      break;
    case SELENE_CS__UNUSED0:
    case SELENE_CS__MAX:
      SLN_ASSERT(1);
      break;
  }
}

static selene_error_t*
init_params(selene_t *s)
{
  sln_parser_baton_t *baton = s->backend_baton;

  if (baton->params_init == 1) {
    return SELENE_SUCCESS;
  }

  {
    sln_params_t *clientp;
    sln_params_t *serverp;
    size_t maclen = 0;
    size_t keylen = 0;
    size_t ivlen = 0;
    size_t outlen = 0;
    size_t off = 0;
    char buf[64];
    char kebuf[SLN_PARAMS_KR_MAX_LENGTH];

    if (s->mode == SLN_MODE_CLIENT) {
      clientp = &baton->active_send_parameters;
      serverp = &baton->active_recv_parameters;
    }
    else {
      serverp = &baton->active_send_parameters;
      clientp = &baton->active_recv_parameters;
    }


    outlen = (maclen * 2) + (keylen * 2) + (ivlen * 2);

    get_suite_info(serverp->suite, &maclen, &keylen, &ivlen);

    SLN_ASSERT(outlen <= SLN_PARAMS_KR_MAX_LENGTH);

    SLN_ASSERT(serverp->suite == clientp->suite);

    memcpy(buf, &baton->server_utc_unix_time, 32);
    memcpy(buf + 32, &baton->client_utc_unix_time, 32);

    sln_prf(s, "key expansion", strlen("key expansion"),
      baton->master_secret,
      SLN_SECRET_LENGTH,
      buf,
      64,
      kebuf,
      outlen);

    memcpy(clientp->mac_secret, kebuf + off, maclen);
    off += maclen;
    memcpy(serverp->mac_secret, kebuf + off, maclen);
    off += maclen;

    memcpy(clientp->key, kebuf + off, keylen);
    off += keylen;
    memcpy(serverp->key, kebuf + off, keylen);
    off += keylen;

    if (ivlen) {
      memcpy(clientp->iv, kebuf + off, ivlen);
      off += ivlen;
      memcpy(serverp->iv, kebuf + off, ivlen);
      off += ivlen;
    }


    sln_hmac_create(s, SLN_HMAC_SHA1, clientp->mac_secret, maclen, &clientp->hmac);

    sln_hmac_create(s, SLN_HMAC_SHA1, serverp->mac_secret, maclen, &serverp->hmac);

    baton->params_init = 1;
  }

  return SELENE_SUCCESS;
}

selene_error_t*
sln_tls_params_update_mac(selene_t *s, sln_bucket_t *b)
{
  sln_parser_baton_t *baton = s->backend_baton;
  sln_params_t *p;

  init_params(s);

  p = &baton->active_send_parameters;

  /* TODO: impl */
  return SELENE_SUCCESS;
}

selene_error_t*
sln_tls_params_encrypt(selene_t *s, sln_bucket_t *b, sln_bucket_t **out)
{
  sln_parser_baton_t *baton = s->backend_baton;
  sln_params_t *p;

  *out = NULL;

  init_params(s);

  p = &baton->active_send_parameters;

  switch (p->suite) {
    /* TODO: impl */
    case SELENE_CS__UNUSED0:
    case SELENE_CS__MAX:
    case SELENE_CS_RSA_WITH_RC4_128_SHA:
    case SELENE_CS_RSA_WITH_AES_128_CBC_SHA:
    case SELENE_CS_RSA_WITH_AES_256_CBC_SHA:
      break;
  }


  /* TODO: padding, sln_cryptor_blocksize() */
  return SELENE_SUCCESS;
}

