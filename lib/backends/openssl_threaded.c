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
#include "selene_error.h"
#include "sln_buckets.h"
#include "sln_types.h"
#include "sln_assert.h"

static void*
sln_openssl_io_enc_thread(void *baton)
{
  selene_t *s = (selene_t*) baton;
  sln_backend_t *backend = s->backend;
  sln_bucket_t *b;
  do {
    /* wait then process incoming data */
    pthread_mutex_lock(&(backend)->io_enc_mutex);
    pthread_cond_wait(&(backend)->io_enc_cond, &(backend)->io_enc_mutex);

    SLN_RING_FOREACH(b, &(s)->bb_in_enc->list, sln_bucket_t, link)
    {
        SLN_RING_REMOVE(b, link);
    }

    pthread_mutex_unlock(&(backend)->io_enc_mutex);

  } while (1);

  return NULL;
}

static selene_error_t*
sln_openssl_event_cb(selene_t *s, selene_event_e event, void *baton)
{
  switch (event) {
  case SELENE_EVENT_IO_IN_ENC:
      pthread_mutex_lock(&s->backend->io_enc_mutex);
      pthread_cond_signal(&s->backend->io_enc_cond);
      pthread_mutex_unlock(&s->backend->io_enc_mutex);
      break;
  default:
      return selene_error_createf(SELENE_EINVAL, \
                                  "captured backend event %d without handler", \
                                  event); \
  }

  return SELENE_SUCCESS;
}

selene_error_t*
sln_openssl_threaded_create(selene_t *s)
{
  sln_backend_t *b;
  pthread_attr_t attr;

  b = (sln_backend_t*) calloc(1, sizeof(*b));
  s->backend = b;

  /* subscribe to events */
  pthread_mutex_init(&b->io_enc_mutex, NULL);
  pthread_cond_init(&b->io_enc_cond, NULL);
  SELENE_ERR(selene_subscribe(s, SELENE_EVENT_IO_IN_ENC,
                              sln_openssl_event_cb, s));

  /* spawn thread */
  pthread_attr_init(&attr);
  pthread_create(&b->thread_id, &attr, sln_openssl_io_enc_thread, s);
  pthread_attr_destroy(&attr);

  return SELENE_SUCCESS;
}

selene_error_t*
sln_openssl_threaded_destroy(selene_t *s)
{
  if (s && s->backend) {
    pthread_mutex_destroy(&s->backend->io_enc_mutex);
    pthread_cond_destroy(&s->backend->io_enc_cond);
    free(s->backend);
  }
}
