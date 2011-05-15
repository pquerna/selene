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

#ifndef _NATIVE_H_
#define _NATIVE_H_

#include "selene.h"
#include "selene_error.h"
#include "sln_buckets.h"
#include "sln_types.h"
#include "sln_assert.h"

/**
 * RFC 4346 handshake states:
 *
 *      Client                                               Server
 *
 *      ClientHello                  -------->
 *                                                      ServerHello
 *                                                     Certificate*
 *                                               ServerKeyExchange*
 *                                              CertificateRequest*
 *                                   <--------      ServerHelloDone
 *    Certificate*
 *      ClientKeyExchange
 *      CertificateVerify*
 *      [ChangeCipherSpec]
 *      Finished                     -------->
 *                                               [ChangeCipherSpec]
 *                                   <--------             Finished
 *      Application Data             <------->     Application Data
 *
 *             Fig. 1. Message flow for a full handshake
 */

typedef enum {
  SLN_NATIVE_HANDSHAKE__UNUSED0 = 0,
  SLN_NATIVE_HANDSHAKE_CLIENT_SEND_HELLO = 1,
  SLN_NATIVE_HANDSHAKE_CLIENT_WAIT_SERVER_HELLO_DONE = 2,
  SLN_NATIVE_HANDSHAKE_CLIENT_SEND_FINISHED = 3,
  SLN_NATIVE_HANDSHAKE_CLIENT_WAIT_SERVER_FINISHED = 4,
  SLN_NATIVE_HANDSHAKE_CLIENT_APPDATA = 5,
  SLN_NATIVE_HANDSHAKE_SERVER_WAIT_CLIENT_HELLO = 6,
  SLN_NATIVE_HANDSHAKE_SERVER_SEND_SERVER_HELLO_DONE = 7,
  SLN_NATIVE_HANDSHAKE_SERVER_WAIT_CLIENT_FINISHED = 8,
  SLN_NATIVE_HANDSHAKE_SERVER_SEND_FINISHED = 9,
  SLN_NATIVE_HANDSHAKE_SERVER_APPDATA = 10,
  SLN_NATIVE_HANDSHAKE__MAX = 11
} sln_native_handshake_e;

typedef enum sln_native_connstate_e {
  SLN_NATIVE_CONNSTATE_HANDSHAKE,
} sln_native_connstate_e;

typedef struct {
  sln_native_connstate_e connstate;
  sln_native_handshake_e handshake;
  int ready_for_appdata;
  int got_first_packet;
  sln_brigade_t *in_handshake;
  sln_brigade_t *in_alert;
  sln_brigade_t *in_ccs;
  sln_brigade_t *in_application;
  uint8_t peer_version_major;
  uint8_t peer_version_minor;
} sln_native_baton_t;


selene_error_t*
sln_native_state_machine(selene_t *s, sln_native_baton_t *baton);

/**
 * TLS Protocol methods
 */
selene_error_t* sln_native_io_tls_read(selene_t *s, sln_native_baton_t *baton);

selene_error_t* sln_native_io_alert_read(selene_t *s, sln_native_baton_t *baton);


/**
 * Client Writing Methods
 */
selene_error_t*
sln_native_io_handshake_client_hello(selene_t *s, sln_native_baton_t *baton);

/**
 * Client Reading Methods
 */


/**
 * Server Writing Methods
 */

/**
 * Server Reading Methods
 */
selene_error_t*
sln_native_io_handshake_read(selene_t *s, sln_native_baton_t *baton);


typedef enum {
  SLN_NATIVE_CONTENT_TYPE__UNUSED0 = 0,
  SLN_NATIVE_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 1,
  SLN_NATIVE_CONTENT_TYPE_ALERT = 2,
  SLN_NATIVE_CONTENT_TYPE_HANDSHAKE = 3,
  SLN_NATIVE_CONTENT_TYPE_APPLICATION = 4,
  SLN_NATIVE_CONTENT_TYPE__MAX = 5
} sln_native_content_type_e;

typedef struct sln_native_msg_tls_t {
  sln_native_content_type_e content_type;
  uint8_t version_major;
  uint8_t version_minor;
  int length;
} sln_native_msg_tls_t;

selene_error_t*
sln_tls_unparse_header(selene_t *s, sln_native_msg_tls_t *tls, sln_bucket_t **b);

#endif
