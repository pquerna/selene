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
#include <string.h>

/* TODO: move to better place */
#define HS_MSG_TYPE_CLIENT_HELLO 1
#define HS_MSG_TYPE_SERVER_HELLO 2


selene_error_t*
sln_native_msg_handshake_client_hello_to_bucket(sln_native_msg_client_hello_t *ch, sln_bucket_t **p_b)
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

  sln_bucket_create_empty(&b, len);

  b->data[0] = HS_MSG_TYPE_CLIENT_HELLO;
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

  b->data[off] = ch->ciphers->used >> 8;
  b->data[off+1] = ch->ciphers->used;
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

