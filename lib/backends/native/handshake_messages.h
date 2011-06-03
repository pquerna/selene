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

#include "sln_tok.h"

#ifndef _handshake_messages_h_
#define _handshake_messages_h_


/* TODO: move to better place */
#define SLN_HS_MSG_TYPE_CLIENT_HELLO 1
#define SLN_HS_MSG_TYPE_SERVER_HELLO 2

typedef enum sln_hs_mt_e {
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
  SLN_HS_MT_HELLO_REQUEST = 0,
  SLN_HS_MT_CLIENT_HELLO = 1,
  SLN_HS_MT_SERVER_HELLO = 2,
  SLN_HS_MT_CERTIFICATE = 11,
  SLN_HS_MT_SERVER_KEY_EXCHANGE = 12,
  SLN_HS_MT_CERTIFICATE_REQUEST = 13,
  SLN_HS_MT_SERVER_HELLO_DONE = 14,
  SLN_HS_MT_CERTIFICATE_VERIFY = 15,
  SLN_HS_MT_CLIENT_KEY_EXCHANGE = 16,
  SLN_HS_MT_FINISHED = 20,
} sln_hs_mt_e;

typedef enum sln_handshake_state_e {
  SLN_HS__UNUSED,
  SLN_HS__INIT,
  SLN_HS_MESSAGE_TYPE,
  SLN_HS_LENGTH,
  SLN_HS_MESSAGE_PARSER,
  SLN_HS__DONE,
  SLN_HS__MAX,
} sln_handshake_state_e;

typedef enum sln_handshake_client_hello_state_e {
  SLN_HS_CLIENT_HELLO_VERSION,
  SLN_HS_CLIENT_HELLO_UTC,
  SLN_HS_CLIENT_HELLO_RANDOM,
  SLN_HS_CLIENT_HELLO_SESSION_LENGTH,
  SLN_HS_CLIENT_HELLO_SESSION_ID,
  SLN_HS_CLIENT_HELLO_CIPHER_SUITES_LENGTH,
  SLN_HS_CLIENT_HELLO_CIPHER_SUITES,
  SLN_HS_CLIENT_HELLO_COMPRESSION,
  SLN_HS_CLIENT_HELLO_EXT_LENGTH,
  SLN_HS_CLIENT_HELLO_EXT_TYPE,
  SLN_HS_CLIENT_HELLO_EXT_SNI_LENGTH,
  SLN_HS_CLIENT_HELLO_EXT_SNI_VALUE,
} sln_handshake_client_hello_state_e;

typedef struct sln_native_msg_client_hello_t {
  uint8_t version_major;
  uint8_t version_minor;
  uint32_t utc_unix_time;
  char random_bytes[28];
  uint8_t session_id_len;
  char session_id[32];
  selene_cipher_suite_list_t *ciphers;
  const char *server_name;
  int have_npn;
  int have_ocsp_stapling;
} sln_native_msg_client_hello_t;

typedef struct sln_hs_baton_t sln_hs_baton_t;

typedef selene_error_t* (sln_hs_msg_step_cb)(sln_hs_baton_t* hs, sln_tok_value_t *v, void *baton);
typedef void (sln_hs_msg_destroy_cb)(sln_hs_baton_t* hs, void *baton);

struct sln_hs_baton_t {
  selene_t *s;
  sln_handshake_state_e state;
  sln_native_baton_t *baton;
  uint8_t message_type;
  uint32_t length;
  void *current_msg_baton;
  sln_hs_msg_step_cb* current_msg_step;
  sln_hs_msg_destroy_cb* current_msg_destroy;
};


selene_error_t*
sln_handshake_unparse_client_hello(selene_t *s, sln_native_msg_client_hello_t *ch, sln_bucket_t **b);

selene_error_t*
sln_handshake_parse_client_hello_setup(sln_hs_baton_t *hs, sln_tok_value_t *v, void **baton);

selene_error_t*
sln_handshake_parse_client_hello_step(sln_hs_baton_t *hs, sln_tok_value_t *v, void *baton);

void
sln_handshake_parse_client_hello_destroy(sln_hs_baton_t *hs, void *baton);

selene_error_t* sln_handshake_handle_client_hello(selene_t *ctxt, selene_event_e event, void *baton_);

#endif

