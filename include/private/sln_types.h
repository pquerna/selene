/*
 * Licensed to Paul Querna under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * Paul Querna licenses this file to You under the Apache License, Version 2.0
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


#ifndef _sln_types_h_
#define _sln_types_h_

#include "selene.h"
#include "sln_log.h"
#include "sln_ring.h"

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

typedef struct sln_bucket_t sln_bucket_t;
typedef struct sln_brigade_t sln_brigade_t;

/* A chunk of memory */
struct sln_bucket_t {
  SLN_RING_ENTRY(sln_bucket_t) link;
  /* When destroying this bucket, can we also destroy memory */
  int memory_is_mine;
  size_t size;
  /* TODO: non-memory buckets */
  char *data;
};

/* A list of chunks (aka, a bucket brigade) */
struct sln_brigade_t {
  SLN_RING_HEAD(sln_bucket_list, sln_bucket_t) list;
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

typedef struct {
  pthread_t thread_id;    
  pthread_mutex_t io_enc_mutex;
  pthread_cond_t io_enc_cond;
} sln_backend_t;

struct selene_t {
  sln_mode_e mode;
  sln_state_e state;

  sln_log_level_e log_level;
  const char *log_msg;
  size_t log_msg_len;
  sln_log_level_e log_msg_level;

  sln_brigade_t *bb_in_enc;
  sln_brigade_t *bb_out_enc;
  sln_brigade_t *bb_in_cleartext;
  sln_brigade_t *bb_out_cleartext;
  sln_events_t *events;

  sln_backend_t *backend;
};

#endif
