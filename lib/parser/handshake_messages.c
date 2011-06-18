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
#include "handshake_messages.h"
#include <string.h>

selene_error_t*
sln_handshake_unparse_client_hello(selene_t *s, sln_msg_client_hello_t *ch, sln_bucket_t **p_b)
{
  sln_bucket_t *b = NULL;
  size_t off = 0;

  int num_extensions = 0;
  size_t extlen = 0;
  size_t len = 0;
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
  dlen = len - 4;
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

  assert(off == len);

  *p_b = b;

  return SELENE_SUCCESS;
}

typedef struct ch_baton_t {
  sln_handshake_client_hello_state_e state;
  sln_msg_client_hello_t ch;
  int cipher_suites_num;
  int compression_num;
} ch_baton_t;

selene_error_t*
sln_handshake_parse_client_hello_setup(sln_hs_baton_t *hs, sln_tok_value_t *v, void **baton)
{
  ch_baton_t *chb = sln_calloc(hs->s, sizeof(ch_baton_t));
  chb->state = SLN_HS_CLIENT_HELLO_VERSION;
  hs->baton->msg.client_hello = &chb->ch;
  v->next = TOK_COPY_BYTES;
  v->wantlen = 2;
  *baton = (void*)chb;
  return SELENE_SUCCESS;
}

selene_error_t*
sln_handshake_parse_client_hello_step(sln_hs_baton_t *hs, sln_tok_value_t *v, void *baton)
{
  selene_error_t *err = SELENE_SUCCESS;
  ch_baton_t *chb = (ch_baton_t*)baton;
  sln_msg_client_hello_t *ch = &chb->ch;
  selene_t *s = hs->s;

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
      memcpy(&ch->utc_unix_time, &v->v.bytes[0], 4);
      chb->state = SLN_HS_CLIENT_HELLO_RANDOM;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 28;
      break;
    }

    case SLN_HS_CLIENT_HELLO_RANDOM:
    {
      memcpy(&ch->random_bytes[0], &v->v.bytes[0], 28);
      chb->state = SLN_HS_CLIENT_HELLO_SESSION_LENGTH;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 1;
      break;
    }

    case SLN_HS_CLIENT_HELLO_SESSION_LENGTH:
    {
      ch->session_id_len = v->v.bytes[0];
      if (ch->session_id_len > 32) {
        /* TODO: session id errors*/
      }
      slnDbg(s, "got session length: %d", ch->session_id_len);

      if (ch->session_id_len == 0) {
        chb->state = SLN_HS_CLIENT_HELLO_CIPHER_SUITES_LENGTH;
        v->next = TOK_UINT16;
        v->wantlen = 2;
      }
      else {
        chb->state = SLN_HS_CLIENT_HELLO_SESSION_ID;
        v->next = TOK_COPY_BYTES;
        v->wantlen = ch->session_id_len;
      }
      break;
    }

    case SLN_HS_CLIENT_HELLO_SESSION_ID:
    {
      memcpy(&ch->session_id[0], &v->v.bytes[0], ch->session_id_len);
      chb->state = SLN_HS_CLIENT_HELLO_CIPHER_SUITES_LENGTH;
      v->next = TOK_UINT16;
      v->wantlen = 1;
      break;
    }

    case SLN_HS_CLIENT_HELLO_CIPHER_SUITES_LENGTH:
    {
      uint16_t cipher_suites_len = v->v.uint16;
      chb->state = SLN_HS_CLIENT_HELLO_CIPHER_SUITES;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 2;
      if (cipher_suites_len % 2 == 1) {
        /* TODO: fatal error */
      }

      /* TODO: max number of cipher suites? */
      chb->cipher_suites_num = cipher_suites_len / 2;
      slnDbg(s, "got cipher suites length: %d numCiphers: %d", cipher_suites_len, chb->cipher_suites_num);
      if (ch->ciphers == NULL) {
        err = selene_cipher_suite_list_create(&ch->ciphers);
      }
      break;
    }

    case SLN_HS_CLIENT_HELLO_CIPHER_SUITES:
    {
      selene_cipher_suite_e suite = SELENE_CS__UNUSED0;
      chb->cipher_suites_num--;

      /* TODO: all other cipher suites */
      /* TODO: centralize */
      switch (v->v.bytes[0]) {
        case 0x00:
          switch (v->v.bytes[1]) {
            case 0x05:
              suite = SELENE_CS_RSA_WITH_RC4_128_SHA;
              break;
            case 0x2F:
              suite = SELENE_CS_RSA_WITH_AES_128_CBC_SHA;
              break;
            case 0x35:
              suite = SELENE_CS_RSA_WITH_AES_256_CBC_SHA;
              break;
            default:
              break;
          }
          break;
        default:
          break;
      }

      if (suite != SELENE_CS__UNUSED0) {
        selene_cipher_suite_list_add(ch->ciphers, suite);
      }

      if (chb->cipher_suites_num <= 0) {
        chb->state = SLN_HS_CLIENT_HELLO_COMPRESSION_LENGTH;
        v->next = TOK_COPY_BYTES;
        v->wantlen = 1;
      }
      else {
        chb->state = SLN_HS_CLIENT_HELLO_CIPHER_SUITES;
        v->next = TOK_COPY_BYTES;
        v->wantlen = 2;
      }
      break;
    }

    case SLN_HS_CLIENT_HELLO_COMPRESSION_LENGTH:
    {
      /* TODO: validate max compression */
      chb->compression_num = v->v.bytes[0];
      chb->state = SLN_HS_CLIENT_HELLO_COMPRESSION;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 1;
      break;
    }

    case SLN_HS_CLIENT_HELLO_COMPRESSION:
      /* TODO: support non-NULL compression, for now we just skip over this */
      chb->compression_num--;
      slnDbg(s, "compression type: %u\n", (unsigned int)v->v.bytes[0]);
      if (chb->compression_num <= 0) {
        chb->state = SLN_HS_CLIENT_HELLO_EXT_DEF;
        v->next = TOK_COPY_BYTES;
        v->wantlen = 4;
      }
      else {
        chb->state = SLN_HS_CLIENT_HELLO_COMPRESSION;
        v->next = TOK_COPY_BYTES;
        v->wantlen = 1;
      }
      break;
    case SLN_HS_CLIENT_HELLO_EXT_DEF:
    {
      /* Extensions Registry:
       *   <http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml>
      */
      uint16_t ext_len = (((unsigned char)v->v.bytes[0]) << 8 |  ((unsigned char)v->v.bytes[1]));
      uint16_t ext_type = (((unsigned char)v->v.bytes[2]) << 8 |  ((unsigned char)v->v.bytes[3]));
      slnDbg(s, "extension: %u len: %u\n", ext_type, ext_len);
      if (ext_type == 0) {
        /* SNI */
        chb->state = SLN_HS_CLIENT_HELLO_EXT_SNI_LENGTH;
        v->next = TOK_UINT16;
        v->wantlen = 2;
      }
      else {
        chb->state = SLN_HS_CLIENT_HELLO_EXT_SKIP;
        v->next = TOK_SKIP;
        v->wantlen = ext_len - 4;
      }
      break;
    }

    case SLN_HS_CLIENT_HELLO_EXT_SKIP:
    {
      chb->state = SLN_HS_CLIENT_HELLO_EXT_DEF;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 4;
      break;
    }

    case SLN_HS_CLIENT_HELLO_EXT_SNI_LENGTH:
    {
      uint16_t sni_len = v->v.uint16;
      chb->state = SLN_HS_CLIENT_HELLO_EXT_SNI_VALUE;
      v->next = TOK_COPY_BRIGADE;
      v->wantlen = sni_len;
      break;
    }

    case SLN_HS_CLIENT_HELLO_EXT_SNI_VALUE:
      /* TODO: flatten SNI name */
      chb->state = SLN_HS_CLIENT_HELLO_EXT_DEF;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 4;
      break;
  }

  return err;
}

selene_error_t*
sln_handshake_parse_client_hello_finish(sln_hs_baton_t *hs, void *baton)
{
  return selene_publish(hs->s, SELENE__EVENT_HS_GOT_CLIENT_HELLO);
}

void
sln_handshake_parse_client_hello_destroy(sln_hs_baton_t *hs, void *baton)
{
  ch_baton_t *chb = (ch_baton_t*)baton;

  if (chb->ch.server_name != NULL) {
    /* TODO: centralize */
    sln_free(hs->s, (char*)chb->ch.server_name);
  }

  if (chb->ch.ciphers != NULL) {
    selene_cipher_suite_list_destroy(chb->ch.ciphers);
  }

  sln_free(hs->s, chb);
}


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
      sh->utc_unix_time = v->v.bytes[0];
      shb->state = SLN_HS_SERVER_HELLO_RANDOM;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 4;
      break;
    }

    case SLN_HS_SERVER_HELLO_RANDOM:
    case SLN_HS_SERVER_HELLO_SESSION_LENGTH:
    case SLN_HS_SERVER_HELLO_SESSION_ID:
    case SLN_HS_SERVER_HELLO_CIPHER_SUITE:
    case SLN_HS_SERVER_HELLO_COMPRESSION:
      /* TODO: finish */
      v->next = TOK_DONE;
      v->wantlen = 0;
      selene_publish(hs->s, SELENE__EVENT_HS_GOT_SERVER_HELLO);
      break;
  }

  return SELENE_SUCCESS;
}

void
sln_handshake_parse_server_hello_destroy(sln_hs_baton_t *hs, void *baton)
{
  sh_baton_t *shb = (sh_baton_t*)baton;

  sln_free(hs->s, shb);
}
