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


#include "selene.h"
#include "sln_types.h"
#include "sln_assert.h"

static void*
sln_openssl_backend(void *baton)
{
  sln_crypto_backend_t *b = ((selene_t*) baton)->backend;
  do {
    sln_backend_msg_t *msg;

    /* wait on queue data */
    pthread_mutex_lock(&b->thread_mutex);
    pthread_cond_wait(&b->thread_cond, &b->thread_mutex);

    msg = SLN_RING_FIRST(&(b)->queue);
    SLN_RING_REMOVE(msg, link);

    pthread_mutex_unlock(&b->thread_mutex);

  } while (1);

  return NULL;
}

selene_error_t*
sln_openssl_threaded_create(selene_t *s)
{
  sln_crypto_backend_t *b;
  pthread_attr_t attr;

  b = calloc(1, sizeof(sln_crypto_backend_t));

  pthread_attr_init(&attr);

  pthread_mutex_init(&b->thread_mutex, NULL);
  pthread_cond_init(&b->thread_cond, NULL);
  pthread_create(&b->thread_id, &attr, sln_openssl_backend, s);

  pthread_attr_destroy(&attr);

  s->backend = b;
      
  return SELENE_SUCCESS;
}

selene_error_t*
sln_crypto_backend_send(selene_t *s, sln_backend_msg_t *msg)
{
  /* TODO: Who owns the message ? */
  sln_crypto_backend_t *b = s->backend;

  pthread_mutex_lock(&(b)->thread_mutex);

  SLN_RING_INSERT_TAIL(&(b)->queue, msg, sln_backend_msg_t, link);

  pthread_cond_signal(&(b)->thread_cond);
  pthread_mutex_unlock(&(b)->thread_mutex);

  return SELENE_SUCCESS;
}

