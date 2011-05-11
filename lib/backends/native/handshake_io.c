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
  ch.version_minor = 2;
  ch.utc_unix_time = time(NULL);

  /* TODO: make sln method for this */
  RAND_bytes((unsigned char *)&ch.random_bytes[0], sizeof(ch.random_bytes));
//  memset(&ch.random_bytes[0], 0xFF, sizeof(ch.random_bytes));

  ch.session_id_len = 0;
  ch.ciphers = &s->conf->ciphers;
  ch.server_name = NULL;
  ch.have_npn = 0;
  ch.have_ocsp_stapling = 0;
  SELENE_ERR(sln_native_msg_handshake_client_hello_to_bucket(&ch, &bhs));

  tls.content_type = SLN_NATIVE_CONTENT_TYPE_HANDSHAKE;
  tls.version_major = 3;
  tls.version_minor = 2;
  tls.length = bhs->size;

  SELENE_ERR(sln_native_msg_tls_to_bucket(&tls, &btls));


  SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, btls);

  SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, bhs);

  return SELENE_SUCCESS;
}

typedef enum handshake_state_e {
  HS__UNUSED,
  HS__INIT,
  HS_MESSAGE_TYPE,
  HS_LENGTH,
  HS_CLIENT_HELLO_VERSION,
  HS_CLIENT_HELLO_UTC,
  HS_CLIENT_HELLO_RANDOM,
  HS_CLIENT_HELLO_SESSION_LENGTH,
  HS_CLIENT_HELLO_SESSION_ID,
  HS_CLIENT_HELLO_CIPHER_SUITES_LENGTH,
  HS_CLIENT_HELLO_CIPHER_SUITES,
  HS_CLIENT_HELLO_COMPRESSION,
  HS_CLIENT_HELLO_EXT_LENGTH,
  HS_CLIENT_HELLO_EXT_TYPE,
  HS_CLIENT_HELLO_EXT_SNI_LENGTH,
  HS_CLIENT_HELLO_EXT_SNI_VALUE,
  HS__DONE,
  HS__MAX,
} handshake_state_e;


typedef struct hs_baton_t {
  selene_t *s;
  handshake_state_e state;
  sln_native_baton_t *baton;
  uint8_t message_type;
  uint32_t length;
  void *current_msg;
} hs_baton_t;


typedef enum hs_mt_e {
  /**
    * 0	HelloRequest
    * 1	ClientHello
    * 2	ServerHello
    * 11	Certificate
    * 12	ServerKeyExchange
    * 13	CertificateRequest
    * 14	ServerHelloDone
    * 15	CertificateVerify
    * 16	ClientKeyExchange
    * 20	Finished
    */
  HS_MT_HELLO_REQUEST = 0,
  HS_MT_CLIENT_HELLO = 1,
  HS_MT_SERVER_HELLO = 2,
  HS_MT_CERTIFICATE = 11,
  HS_MT_SERVER_KEY_EXCHANGE = 12,
  HS_MT_CERTIFICATE_REQUEST = 13,
  HS_MT_SERVER_HELLO_DONE = 14,
  HS_MT_CERTIFICATE_VERIFY = 15,
  HS_MT_CLIENT_KEY_EXCHANGE = 16,
  HS_MT_FINISHED = 20,
} hs_mt_e;

static int
is_valid_message_type(uint8_t input) {
  if (input == HS_MT_HELLO_REQUEST ||
      input == HS_MT_CLIENT_HELLO ||
      input == HS_MT_SERVER_HELLO ||
      input == HS_MT_CERTIFICATE ||
      input == HS_MT_SERVER_KEY_EXCHANGE ||
      input == HS_MT_CERTIFICATE_REQUEST ||
      input == HS_MT_SERVER_HELLO_DONE ||
      input == HS_MT_CERTIFICATE_VERIFY ||
      input == HS_MT_CLIENT_KEY_EXCHANGE ||
      input == HS_MT_FINISHED) {
    return 1;
  }
  return 0;
}

static selene_error_t*
read_handshake_parser(sln_tok_value_t *v, void *baton_)
{
  hs_baton_t *hs = (hs_baton_t*)baton_;
  switch (hs->state) {
    case HS__INIT:
      hs->state = HS_MESSAGE_TYPE;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 1;
      break;
    case HS_MESSAGE_TYPE:
      hs->message_type = v->v.bytes[0];
      if (!is_valid_message_type(hs->message_type)) {
        return selene_error_createf(SELENE_EINVAL, "Invalid handshake message type: %u", hs->message_type);
      }
      hs->state = HS_LENGTH;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 3;
      break;
    case HS_LENGTH:
      hs->length = (((unsigned char)v->v.bytes[0]) << 16 | ((unsigned char)v->v.bytes[1]) << 8 |  ((unsigned char)v->v.bytes[2]));
      /* TODO: handle more message types */
      if (hs->message_type == HS_MT_CLIENT_HELLO) {
        hs->state = HS_CLIENT_HELLO_VERSION;
        v->next = TOK_COPY_BYTES;
        v->wantlen = 2;
      }
      else {
        hs->state = HS__DONE;
        v->next = TOK_DONE;
        v->wantlen = 0;
      }
      break;

    case HS_CLIENT_HELLO_VERSION:
    {
      sln_native_msg_client_hello_t *ch = calloc(1, sizeof(sln_native_msg_client_hello_t));
      hs->current_msg = ch;
      ch->version_major = v->v.bytes[0];
      ch->version_minor = v->v.bytes[1];

      hs->state = HS_CLIENT_HELLO_UTC;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 4;
      break;
    }

    case HS_CLIENT_HELLO_UTC:
    {
      sln_native_msg_client_hello_t *ch = (sln_native_msg_client_hello_t*) hs->current_msg;
      ch->utc_unix_time = v->v.bytes[0] ;
      hs->state = HS__DONE;
      v->next = TOK_DONE;
      v->wantlen = 0;
      break;
    }

    case HS_CLIENT_HELLO_RANDOM:
    case HS_CLIENT_HELLO_SESSION_LENGTH:
    case HS_CLIENT_HELLO_SESSION_ID:
    case HS_CLIENT_HELLO_CIPHER_SUITES_LENGTH:
    case HS_CLIENT_HELLO_CIPHER_SUITES:
    case HS_CLIENT_HELLO_COMPRESSION:
    case HS_CLIENT_HELLO_EXT_LENGTH:
    case HS_CLIENT_HELLO_EXT_TYPE:
    case HS_CLIENT_HELLO_EXT_SNI_LENGTH:
    case HS_CLIENT_HELLO_EXT_SNI_VALUE:
    default:
      hs->state = HS__DONE;
      v->next = TOK_DONE;
      v->wantlen = 0;
  }
  return SELENE_SUCCESS;
}

selene_error_t*
sln_native_io_handshake_read(selene_t *s, sln_native_baton_t *baton)
{
  hs_baton_t hs;

  hs.s = s;
  hs.baton = baton;
  hs.state = HS__INIT;
  hs.current_msg = NULL;

  sln_tok_parser(baton->in_handshake, read_handshake_parser, &hs);

  if (hs.current_msg != NULL) {
    /* TOOD: this is wrrrrrong */
    free(hs.current_msg);
  }

  return SELENE_SUCCESS;
}
