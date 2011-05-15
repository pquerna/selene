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
#include "handshake_messages.h"
#include <string.h>

selene_error_t*
sln_handshake_unparse_client_hello(selene_t *s, sln_native_msg_client_hello_t *ch, sln_bucket_t **p_b)
{
  sln_bucket_t *b = NULL;
  size_t off = 0;

  int num_extensions = 0;
  size_t extlen = 0;
  size_t len = 0;

  /* header size */
  len += 4;

  /* protocol version */
  len += 2;

  /* utc_unix_time */
  len += 4;

  /* random_bytes */
  len += 28;

  /* session id length */
  len += 1;
  len += ch->session_id_len;

  /* Length of cipher suites */
  len += 2;
  len += (ch->ciphers->used * 2);

  /* TODO: Compression */
  /* Compression Length (no support right now) */
  len += 1;

  if (ch->server_name != NULL) {
/*
    num_extensions++;
    extlen += 2;
    extlen += strlen(ch->server_name);
*/
  }

  if (ch->have_npn) {
    num_extensions++;
    /* TODO: npn support */
  }

  if (ch->have_ocsp_stapling) {
    num_extensions++;
    /* TODO: ocsp support */
    abort();
  }

  len += num_extensions * 4;
  len += extlen;

  sln_bucket_create_empty(s->alloc, &b, len);

  b->data[0] = SLN_HS_MSG_TYPE_CLIENT_HELLO;
  int dlen = len - 4;
  b->data[1] = dlen >> 16;
  b->data[2] = dlen >> 8;
  b->data[3] = dlen;
  off = 4;

  b->data[off] = ch->version_major;
  b->data[off+1] = ch->version_minor;
  off += 2;

  b->data[off] = ch->utc_unix_time >> 24;
  b->data[off+1] = ch->utc_unix_time >> 16;
  b->data[off+2] = ch->utc_unix_time >> 8;
  b->data[off+3] = ch->utc_unix_time;
  off += 4;

  memcpy(b->data + off, &ch->random_bytes[0], sizeof(ch->random_bytes));
  off += sizeof(ch->random_bytes);

  b->data[off] = ch->session_id_len;
  off += 1;

  if (ch->session_id_len != 0) {
    memcpy(b->data + off, &ch->session_id[0], ch->session_id_len);
    off += ch->session_id_len;
  }

  /* Length of the Cipher Suites in bytes */
  b->data[off] = ch->ciphers->used * 2 >> 8;
  b->data[off+1] = ch->ciphers->used * 2;
  off += 2;

  for (int i = 0; i < ch->ciphers->used; i++) {
    switch (ch->ciphers->ciphers[i]) {
      /* TODO: move a better utility place */
      case SELENE_CS_RSA_WITH_RC4_128_SHA:
        b->data[off] = 0x00;
        b->data[off+1] = 0x05;
        break;
      case SELENE_CS_RSA_WITH_AES_128_CBC_SHA:
        b->data[off] = 0x00;
        b->data[off+1] = 0x2F;
        break;
      case SELENE_CS_RSA_WITH_AES_256_CBC_SHA:
        b->data[off] = 0x00;
        b->data[off+1] = 0x35;
        break;
      default:
        /* TODO: handle this */
        abort();
        break;
    }
    off += 2;
  }

  /* Compression... no */
  b->data[off] = 0;
  off += 1;

  *p_b = b;

  return SELENE_SUCCESS;
}

typedef struct ch_baton_t {
  sln_handshake_client_hello_state_e state;
  sln_native_msg_client_hello_t ch;
} ch_baton_t;

selene_error_t*
sln_handshake_parse_client_hello_setup(sln_hs_baton_t *hs, sln_tok_value_t *v, void **baton)
{
  ch_baton_t *chb = sln_calloc(hs->s, sizeof(ch_baton_t));
  chb->state = SLN_HS_CLIENT_HELLO_VERSION;
  v->next = TOK_COPY_BYTES;
  v->wantlen = 2;
  *baton = (void*)chb;
  return SELENE_SUCCESS;
}

selene_error_t*
sln_handshake_parse_client_hello_step(sln_hs_baton_t *hs, sln_tok_value_t *v, void *baton)
{
  ch_baton_t *chb = (ch_baton_t*)baton;
  sln_native_msg_client_hello_t *ch = &chb->ch;

  switch (chb->state) {
    case SLN_HS_CLIENT_HELLO_VERSION:
    {
      ch->version_major = v->v.bytes[0];
      ch->version_minor = v->v.bytes[1];

      chb->state = SLN_HS_CLIENT_HELLO_UTC;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 4;
      break;
    }

    case SLN_HS_CLIENT_HELLO_UTC:
    {
      ch->utc_unix_time = v->v.bytes[0];
      chb->state = SLN_HS_CLIENT_HELLO_RANDOM;
      v->next = TOK_DONE;
      v->wantlen = 0;
      break;
    }

    case SLN_HS_CLIENT_HELLO_RANDOM:
    case SLN_HS_CLIENT_HELLO_SESSION_LENGTH:
    case SLN_HS_CLIENT_HELLO_SESSION_ID:
    case SLN_HS_CLIENT_HELLO_CIPHER_SUITES_LENGTH:
    case SLN_HS_CLIENT_HELLO_CIPHER_SUITES:
    case SLN_HS_CLIENT_HELLO_COMPRESSION:
    case SLN_HS_CLIENT_HELLO_EXT_LENGTH:
    case SLN_HS_CLIENT_HELLO_EXT_TYPE:
    case SLN_HS_CLIENT_HELLO_EXT_SNI_LENGTH:
    case SLN_HS_CLIENT_HELLO_EXT_SNI_VALUE:
      /* TODO: finish */
      v->next = TOK_DONE;
      v->wantlen = 0;
      break;
  }

  return SELENE_SUCCESS;
}

void
sln_handshake_parse_client_hello_destroy(sln_hs_baton_t *hs, void *baton)
{
  ch_baton_t *chb = (ch_baton_t*)baton;

  if (chb->ch.server_name != NULL) {
    /* TODO: centralize */
    sln_free(hs->s, (char*)chb->ch.server_name);
  }

  sln_free(hs->s, chb);
}
