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
sln_handshake_unparse_server_hello(selene_t *s, sln_msg_server_hello_t *sh, sln_bucket_t **p_b)
{
  sln_bucket_t *b = NULL;
  size_t len = 0;
  size_t off;
  int dlen;

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
  len += sh->session_id_len;

  /* cipherSuite */
  len += 2;

  /* compressionMethod */
  len += 1;

  /* TODO: extensions */
  sln_bucket_create_empty(s->alloc, &b, len);

  b->data[0] = SLN_HS_MSG_TYPE_SERVER_HELLO;
  dlen = len - 4;
  b->data[1] = dlen >> 16;
  b->data[2] = dlen >> 8;
  b->data[3] = dlen;
  off = 4;

  b->data[off] = sh->version_major;
  b->data[off+1] = sh->version_minor;
  off += 2;

  b->data[off] = sh->utc_unix_time >> 24;
  b->data[off+1] = sh->utc_unix_time >> 16;
  b->data[off+2] = sh->utc_unix_time >> 8;
  b->data[off+3] = sh->utc_unix_time;
  off += 4;

  memcpy(b->data + off, &sh->random_bytes[0], sizeof(sh->random_bytes));
  off += sizeof(sh->random_bytes);

  b->data[off] = sh->session_id_len;
  off += 1;

  if (sh->session_id_len != 0) {
    memcpy(b->data + off, &sh->session_id[0], sh->session_id_len);
    off += sh->session_id_len;
  }

  switch (sh->cipher) {
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

  b->data[off] = 0;

  off += 1;

  assert(off == len);

  *p_b = b;

  return SELENE_SUCCESS;
}


typedef struct sh_baton_t {
  sln_handshake_server_hello_state_e state;
  sln_msg_server_hello_t sh;
} sh_baton_t;

selene_error_t*
sln_handshake_parse_server_hello_setup(sln_hs_baton_t *hs, sln_tok_value_t *v, void **baton)
{
  sh_baton_t *shb = sln_calloc(hs->s, sizeof(sh_baton_t));
  shb->state = SLN_HS_SERVER_HELLO_VERSION;
  hs->baton->msg.server_hello = &shb->sh;
  v->next = TOK_COPY_BYTES;
  v->wantlen = 2;
  *baton = (void*)shb;
  return SELENE_SUCCESS;
}

selene_error_t*
sln_handshake_parse_server_hello_step(sln_hs_baton_t *hs, sln_tok_value_t *v, void *baton)
{
  sh_baton_t *shb = (sh_baton_t*)baton;
  sln_msg_server_hello_t *sh = &shb->sh;
  selene_t *s = hs->s;

  switch (shb->state) {
    case SLN_HS_CLIENT_HELLO_VERSION:
    {
      sh->version_major = v->v.bytes[0];
      sh->version_minor = v->v.bytes[1];

      shb->state = SLN_HS_SERVER_HELLO_UTC;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 4;
      break;
    }

    case SLN_HS_SERVER_HELLO_UTC:
    {
      memcpy(&sh->utc_unix_time, &v->v.bytes[0], 4);
      shb->state = SLN_HS_SERVER_HELLO_RANDOM;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 28;
      break;
    }

    case SLN_HS_SERVER_HELLO_RANDOM:
    {
      memcpy(&sh->random_bytes[0], &v->v.bytes[0], 28);
      shb->state = SLN_HS_SERVER_HELLO_SESSION_LENGTH;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 1;
      break;
    }

    case SLN_HS_SERVER_HELLO_SESSION_LENGTH:
    {
      sh->session_id_len = v->v.bytes[0];
      if (sh->session_id_len > 32) {
        /* TODO: session id errors */
      }

      if (sh->session_id_len == 0) {
        shb->state = SLN_HS_SERVER_HELLO_CIPHER_SUITE;
        v->next = TOK_COPY_BYTES;
        v->wantlen = 2;
      }
      else {
        shb->state = SLN_HS_SERVER_HELLO_SESSION_ID;
        v->next = TOK_COPY_BYTES;
        v->wantlen = sh->session_id_len;
      }
      break;
    }

    case SLN_HS_SERVER_HELLO_SESSION_ID:
    {
      memcpy(&sh->session_id[0], &v->v.bytes[0], sh->session_id_len);
      shb->state = SLN_HS_SERVER_HELLO_CIPHER_SUITE;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 2;
      break;
    }

    case SLN_HS_SERVER_HELLO_CIPHER_SUITE:
    {
      selene_cipher_suite_e cipher = sln_parser_hs_bytes_to_cipher_suite(v->v.bytes[0], v->v.bytes[1]);

      if (cipher != SELENE_CS__UNUSED0) {
        /* TODO: save, validate its in our list of acceptable suites */
        sh->cipher = cipher;
      }
      else {
        /* TODO: abort connection, we weren't able to agree on a cipher suite */
      }

      shb->state = SLN_HS_SERVER_HELLO_COMPRESSION;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 1;
      break;
    }

    case SLN_HS_SERVER_HELLO_COMPRESSION:
    {
      sh->comp = sln_parser_hs_bytes_to_comp_method(v->v.bytes[0]);
      /* TODO: fatal alert on invalid comp method (?) */
      shb->state = SLN_HS_SERVER_HELLO_EXT_DEF;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 4;
      break;
    }

    case SLN_HS_SERVER_HELLO_EXT_DEF:
    {
      /* Extensions Registry:
       *   <http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml>
      */
      uint16_t ext_len = (((unsigned char)v->v.bytes[0]) << 8 |  ((unsigned char)v->v.bytes[1]));
      uint16_t ext_type = (((unsigned char)v->v.bytes[2]) << 8 |  ((unsigned char)v->v.bytes[3]));

      slnDbg(s, "server extension: %u len: %u\n", ext_type, ext_len);

      if (ext_type == 0) {
        /* SNI  was supported by the server, but we don't care here, so we just skip it */
        shb->state = SLN_HS_SERVER_HELLO_EXT_SKIP;
        v->next = TOK_SKIP;
        v->wantlen = ext_len - 4;
      }
      else {
        shb->state = SLN_HS_SERVER_HELLO_EXT_SKIP;
        v->next = TOK_SKIP;
        v->wantlen = ext_len - 4;
      }
      break;
    }

    case SLN_HS_SERVER_HELLO_EXT_SKIP:
    {
      shb->state = SLN_HS_SERVER_HELLO_EXT_DEF;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 4;
      break;
    }

    /* TODO: support more extensions, NPN */
  }

  return SELENE_SUCCESS;
}

selene_error_t*
sln_handshake_parse_server_hello_finish(sln_hs_baton_t *hs, void *baton)
{
  return selene_publish(hs->s, SELENE__EVENT_HS_GOT_SERVER_HELLO);
}

void
sln_handshake_parse_server_hello_destroy(sln_hs_baton_t *hs, void *baton)
{
  sh_baton_t *shb = (sh_baton_t*)baton;

  sln_free(hs->s, shb);
}
