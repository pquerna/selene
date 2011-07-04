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
#include "common.h"
#include "handshake_messages.h"
#include "sln_tok.h"
#include <string.h>

static selene_error_t*
handle_client_hello(selene_t *s, selene_event_e event, void *baton_)
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
    SELENE_ERR(sln_handshake_serialize_server_hello(s, &sh, &bhs));

    /* TODO: create certificate message for non-PSK ciphers */
    tls.content_type = SLN_CONTENT_TYPE_HANDSHAKE;
    sln_parser_tls_set_current_version(s, &tls.version_major, &tls.version_minor);
    tls.length = bhs->size;

    SELENE_ERR(sln_tls_serialize_header(s, &tls, &btls));

    SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, btls);

    SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, bhs);
  }
  return SELENE_SUCCESS;
}


selene_cert_chain_t*
selene_peer_certchain(selene_t *s)
{
  return NULL;
}

void
selene_complete_peer_certchain_validated(selene_t *s, int valid)
{

}

/* default fallback */
static selene_error_t*
validate_certificates(selene_t *s, selene_event_e event, void *baton)
{
  selene_cert_chain_t* certs = selene_peer_certchain(s);

  if (certs) {
    /* TOOD: inspect certs */
    selene_complete_peer_certchain_validated(s, 1);
  }
  else {
    selene_complete_peer_certchain_validated(s, 0);
  }

  return SELENE_SUCCESS;
}

static selene_error_t*
handle_server_certificate(selene_t *s, selene_event_e event, void *x)
{
  return selene_publish(s, SELENE_EVENT_VALIDATE_CERTIFICATE);
}

void
sln_handshake_register_callbacks(selene_t *s)
{
  if (s->mode == SLN_MODE_CLIENT) {
    selene_handler_set(s, SELENE__EVENT_HS_GOT_CERTIFICATE, handle_server_certificate, NULL);
    selene_handler_set(s, SELENE_EVENT_VALIDATE_CERTIFICATE, validate_certificates, NULL);
  }
  else {
    selene_handler_set(s, SELENE__EVENT_HS_GOT_CLIENT_HELLO, handle_client_hello, NULL);
  }
}

