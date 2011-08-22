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
#include "sln_arrays.h"
#include "sln_rsa.h"
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

  return selene_publish(s, SELENE_EVENT_SELECT_CERTIFICATES);
}

/* default fallback */
static selene_error_t*
select_certificates(selene_t *s, selene_event_e event, void *baton)
{
  /* TODO: matching names and subject alt names */

  selene_complete_select_certificates(s, SLN_ARRAY_IDX(s->conf->certs, 0, selene_cert_chain_t*));

  return SELENE_SUCCESS;
}


static selene_error_t*
send_server_certs(selene_t *s)
{
  sln_parser_baton_t *baton = s->backend_baton;

  SLN_ASSERT(s->my_certs != NULL);

  /* TODO: move to post-finding certificate callback */
  {
    sln_msg_server_hello_t sh;
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

    SELENE_ERR(sln_tls_toss_bucket(s, SLN_CONTENT_TYPE_HANDSHAKE, bhs));
  }

  {
    /* TODO: more handshake extensions, client certificate request support */
    sln_msg_certificate_t cert;
    sln_bucket_t *bcert = NULL;

    cert.chain = s->my_certs;
    SELENE_ERR(sln_handshake_serialize_certificate(s, &cert, &bcert));

    SELENE_ERR(sln_tls_toss_bucket(s, SLN_CONTENT_TYPE_HANDSHAKE, bcert));
  }

  {
    sln_msg_server_hello_done_t done;
    sln_bucket_t *bdone = NULL;

    SELENE_ERR(sln_handshake_serialize_server_hello_done(s, &done, &bdone));

    SELENE_ERR(sln_tls_toss_bucket(s, SLN_CONTENT_TYPE_HANDSHAKE, bdone));
  }

  baton->handshake = SLN_HANDSHAKE_SERVER_WAIT_CLIENT_FINISHED;

  return sln_state_machine(s, baton);
}

void
selene_complete_select_certificates(selene_t *s, selene_cert_chain_t *chain)
{
  sln_parser_baton_t *baton = s->backend_baton;

  if (baton->fatal_err) {
    return;
  }

  s->my_certs = chain;

  if (s->my_certs != NULL) {
    baton->fatal_err = send_server_certs(s);
  }
  else {
    baton->fatal_err = selene_error_create(SELENE_EINVAL, "No certificates selected but in a server mode that requires it.");
  }
}


selene_cert_chain_t*
selene_peer_certchain(selene_t *s)
{
  return s->peer_certs;
}

sln_pubkey_t*
sln_peer_pubkey(selene_t *s)
{
  if (!s->peer_pubkey) {
    selene_cert_t* cert = selene_cert_chain_entry(s->peer_certs, 0);
    s->peer_pubkey = sln_alloc(s, sizeof(sln_pubkey_t));
    s->peer_pubkey->key = X509_get_pubkey(cert->cert);
  }
  return s->peer_pubkey;
}

void
selene_complete_validate_certificate(selene_t *s, int valid)
{
  /* TODO: note this in selene_t8s */
}

/* default fallback */
static selene_error_t*
validate_certificate(selene_t *s, selene_event_e event, void *baton)
{
  selene_cert_chain_t* certs = selene_peer_certchain(s);

  if (certs) {
    /* TOOD: inspect certs */
    selene_complete_validate_certificate(s, 1);
  }
  else {
    selene_complete_validate_certificate(s, 0);
  }

  return SELENE_SUCCESS;
}

static selene_error_t*
handle_server_certificate(selene_t *s, selene_event_e event, void *x)
{
  sln_parser_baton_t *baton = s->backend_baton;
  sln_msg_certificate_t *certs = baton->msg.certificate;
  s->peer_certs = certs->chain;
  certs->chain = NULL;
  return selene_publish(s, SELENE_EVENT_VALIDATE_CERTIFICATE);
}

static selene_error_t*
send_client_key_exhcnage(selene_t *s)
{
  sln_parser_baton_t *baton = s->backend_baton;
  sln_msg_client_key_exchange_t cke;
  sln_pubkey_t *pubkey;
  sln_bucket_t *bcke = NULL;
  char *output;
  size_t outlen;

  slnDbg(s, "sending client key exchange");

  sln_parser_tls_set_current_version(s, (uint8_t *)&baton->pre_master_secret[0], (uint8_t *)&baton->pre_master_secret[1]);

  sln_parser_rand_bytes_secure(baton->pre_master_secret + 2, SLN_SECRET_LENGTH - 2);

  pubkey = sln_peer_pubkey(s);

  outlen = sln_rsa_size(pubkey);
  output = sln_alloc(s, outlen);

  SELENE_ERR(sln_rsa_public_encrypt(s, pubkey, baton->pre_master_secret, SLN_SECRET_LENGTH, output));
  cke.pre_master_secret_length = outlen;
  cke.pre_master_secret = output;

  SELENE_ERR(sln_handshake_serialize_client_key_exchange(s, &cke, &bcke));
  SELENE_ERR(sln_tls_toss_bucket(s, SLN_CONTENT_TYPE_HANDSHAKE, bcke));

  sln_free(s, output);

  return SELENE_SUCCESS;
}

static selene_error_t*
send_change_cipher_spec(selene_t *s)
{
  sln_msg_change_cipher_spec_t ccs;
  sln_bucket_t *bccs = NULL;

  slnDbg(s, "sending change cipher spec");

  SELENE_ERR(sln_handshake_serialize_change_cipher_spec(s, &ccs, &bccs));

  SELENE_ERR(sln_tls_toss_bucket(s, SLN_CONTENT_TYPE_CHANGE_CIPHER_SPEC, bccs));

  return SELENE_SUCCESS;
}

static selene_error_t*
send_finished(selene_t *s)
{
  sln_msg_finished_t fin;
  sln_bucket_t *bfin = NULL;

  slnDbg(s, "sending finished");

  SELENE_ERR(sln_handshake_serialize_finished(s, &fin, &bfin));

  SELENE_ERR(sln_tls_toss_bucket(s, SLN_CONTENT_TYPE_HANDSHAKE, bfin));

  return SELENE_SUCCESS;
}

static selene_error_t*
handle_server_done(selene_t *s, selene_event_e event, void *x)
{
  SELENE_ERR(send_client_key_exhcnage(s));
  /* TODO: cert verify */
  SELENE_ERR(send_change_cipher_spec(s));
  SELENE_ERR(send_finished(s));

  return SELENE_SUCCESS;
}

void
sln_handshake_register_callbacks(selene_t *s)
{
  if (s->mode == SLN_MODE_CLIENT) {
    selene_handler_set(s, SELENE__EVENT_HS_GOT_CERTIFICATE, handle_server_certificate, NULL);
    selene_handler_set(s, SELENE__EVENT_HS_GOT_SERVER_HELLO_DONE, handle_server_done, NULL);
    selene_handler_set(s, SELENE_EVENT_VALIDATE_CERTIFICATE, validate_certificate, NULL);
  }
  else {
    selene_handler_set(s, SELENE__EVENT_HS_GOT_CLIENT_HELLO, handle_client_hello, NULL);
    selene_handler_set(s, SELENE_EVENT_SELECT_CERTIFICATES, select_certificates, NULL);
  }
}

