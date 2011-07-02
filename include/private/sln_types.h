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


#include "selene.h"
#include "sln_log.h"
#include "sln_ring.h"
#include "selene_cert.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

#ifndef _sln_types_h_
#define _sln_types_h_

/* TODO: public header? */
typedef enum {
  SLN_STATE__UNUSED0 = 0,
  SLN_STATE_INIT = 1,
  SLN_STATE_DEAD = 2,
  SLN_STATE__MAX = 3
} sln_state_e;

typedef enum {
  SLN_MODE__UNUSED0 = 0,
  SLN_MODE_CLIENT = 1,
  SLN_MODE_SERVER = 2,
  SLN_MODE__MAX = 3
} sln_mode_e;

typedef enum {
  SLN_BACKEND__UNUSED0 = 0,
  SLN_BACKEND_NATIVE = 1,
  SLN_BACKEND__MAX = 2
} sln_backend_e;

typedef struct sln_bucket_t sln_bucket_t;
typedef struct sln_brigade_t sln_brigade_t;

/* A chunk of memory */
struct sln_bucket_t {
  SLN_RING_ENTRY(sln_bucket_t) link;
  selene_alloc_t *alloc;
  /* When destroying this bucket, can we also destroy memory */
  int memory_is_mine;
  size_t size;
  /* TODO: non-memory buckets */
  char *data;
};

/* A list of chunks (aka, a bucket brigade) */
struct sln_brigade_t {
  SLN_RING_HEAD(sln_bucket_list, sln_bucket_t) list;
  selene_alloc_t *alloc;
};

typedef struct sln_eventcb_t sln_eventcb_t;
typedef struct sln_events_t sln_events_t;

struct sln_eventcb_t {
  SLN_RING_ENTRY(sln_eventcb_t) link;
  selene_event_cb *cb;
  void *baton;
};

struct sln_events_t {
  SLN_RING_HEAD(sln_events_list, sln_eventcb_t) list;
  selene_event_e event;
  selene_event_cb *handler;
  void *handler_baton;
};

typedef enum {
  SLN_TLS_VERSION__UNUSED0 = 0,
  SLN_TLS_VERSION_SSL30 = 1,
  SLN_TLS_VERSION_TLS10 = 2,
  SLN_TLS_VERSION_TLS11 = 3,
  SLN_TLS_VERSION_TLS12 = 4,
  SLN_TLS_VERSION__MAX = 5
} sln_tls_version_e;

typedef enum {
  SLN_TLS_CTYPE__UNUSED0 = 0,
  SLN_TLS_CTYPE_CHANGE_CIPHER_SPEC = 1,
  SLN_TLS_CTYPE_ALERT = 2,
  SLN_TLS_CTYPE_HANDSHAKE = 3,
  SLN_TLS_CTYPE_APPLICTION_DATA = 4,
  SLN_TLS_CTYPE__MAX = 5
} sln_tls_ctype_e;

/* Repersents our parsed version of the TLS record,
 * not really what we send out on the wire */
typedef struct {
  sln_tls_ctype_e content_type;
  sln_tls_version_e version;
  size_t protocol_size;
  void *protocol_data;
} sln_tls_record_t;

typedef selene_error_t* (sln_standard_cb)(selene_t *ctxt);
typedef selene_error_t* (sln_standard_baton_cb)(selene_t *ctxt, void *baton);

typedef struct {
  const char *name;
  sln_standard_cb *create;
  sln_standard_cb *start;
  sln_standard_cb *destroy;
} sln_backend_t;

struct selene_cipher_suite_list_t {
  int used;
  int ciphers[SELENE_CS__MAX];
};

struct selene_conf_t {
  selene_alloc_t *alloc;
  int protocols;
  selene_cipher_suite_list_t ciphers;
  X509_STORE* trusted_cert_store;
};

struct selene_cert_t {
  selene_t *s;
  X509 *cert;
  int depth;
  /* Cache extracted information out of the certificate. */
  const char *cache_fingerprint_sha1;
  const char *cache_fingerprint_md5;
  const char *cache_not_before;
  const char *cache_not_after;
  selene_cert_name_t *cache_subject;
  selene_cert_name_t *cache_issuer;
  int cache_alt_names_len;
  char **cache_alt_names;
};


typedef struct {
  sln_brigade_t *in_enc;
  sln_brigade_t *out_enc;
  sln_brigade_t *in_cleartext;
  sln_brigade_t *out_cleartext;
} sln_iobb_t;

struct selene_t {
  selene_alloc_t *alloc;
  sln_mode_e mode;
  sln_state_e state;
  selene_conf_t *conf;

  sln_log_level_e log_level;
  const char *log_msg;
  size_t log_msg_len;
  sln_log_level_e log_msg_level;

  sln_iobb_t bb;
  sln_events_t *events;

  sln_backend_t backend;
  void *backend_baton;

  const char *client_sni;
};

void* sln_alloc(selene_t *s, size_t len);
void* sln_calloc(selene_t *s, size_t len);
void sln_free(selene_t *s, void *ptr);
char *sln_strdup(selene_t *s, const char *in);

#define SLN_ERR_CLIENT_ONLY(s) do { \
  if (s->conf.mode != SLN_MODE_CLIENT) { \
    return selene_error_createf(SELENE_EINVAL, \
    "%s is only available in client mode", __func__); \
  } \
} while(0);

#define SLN_ERR_SERVER_ONLY(s) do { \
  if (s->conf.mode != SLN_MODE_SERVER) { \
    return selene_error_createf(SELENE_EINVAL, \
    "%s is only available in client mode", __func__); \
  } \
} while(0);

#endif
