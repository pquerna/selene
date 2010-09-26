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

#ifndef _OPENSSL_THREADED_H_
#define _OPENSSL_THREADED_H_

#include "selene.h"
#include "selene_error.h"
#include "sln_buckets.h"
#include "sln_types.h"
#include "sln_assert.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct sln_mainthread_cb_t sln_mainthread_cb_t;

struct sln_mainthread_cb_t {
  SLN_RING_ENTRY(sln_mainthread_cb_t) link;
  sln_standard_baton_cb *cb;
  void *baton;
};

#define SLN_MT_INSERT_TAIL(b, e) \
  do { \
    sln_mainthread_cb_t *sln__cbt = (e); \
    SLN_RING_INSERT_TAIL(&(b)->list, sln__cbt, sln_mainthread_cb_t, link); \
  } while (0)

typedef struct {
  int should_exit;
  selene_error_t *err;
  pthread_t thread_id;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  SSL_METHOD *meth;
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *bio_read;
  BIO *bio_write;
  int want;
  SLN_RING_HEAD(sln_mainthread_list, sln_mainthread_cb_t) list;
  sln_iobb_t bb;
} sln_ot_baton_t;


char* sln_ot_ciphers_to_openssl(int selene_ciphers);

void* sln_ot_io_thread(void *thread_baton);

selene_error_t* sln_ot_event_cycle(selene_t *s);
selene_error_t* sln_ot_event_cb(selene_t *s, selene_event_e event, void *unused_baton);

#endif
