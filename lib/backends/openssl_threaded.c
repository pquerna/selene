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

typedef struct {
  pthread_t thread_id;
  pthread_mutex_t io_enc_mutex;
  pthread_cond_t io_enc_cond;
} sln_ot_baton_t;


static void*
sln_openssl_io_enc_thread(void *thread_baton)
{
  selene_t *s = (selene_t*) thread_baton;
  sln_ot_baton_t *baton = s->backend_baton;
  sln_bucket_t *b;
  do {
    /* wait then process incoming data */
    pthread_mutex_lock(&(baton)->io_enc_mutex);
    pthread_cond_wait(&(baton)->io_enc_cond, &(baton)->io_enc_mutex);

    SLN_RING_FOREACH(b, &(s)->bb_in_enc->list, sln_bucket_t, link)
    {
        SLN_RING_REMOVE(b, link);
    }

    pthread_mutex_unlock(&(baton)->io_enc_mutex);

  } while (1);

  return NULL;
}

static selene_error_t*
sln_openssl_event_cb(selene_t *s, selene_event_e event, void *unused_baton)
{
  sln_ot_baton_t *baton = s->backend_baton;

  switch (event) {
  case SELENE_EVENT_IO_IN_ENC:
      pthread_mutex_lock(&baton->io_enc_mutex);
      pthread_cond_signal(&baton->io_enc_cond);
      pthread_mutex_unlock(&baton->io_enc_mutex);
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
  sln_ot_baton_t *baton;
  pthread_attr_t attr;

  baton = (sln_ot_baton_t*) calloc(1, sizeof(*baton));
  s->backend_baton = baton;

  /* subscribe to events */
  pthread_mutex_init(&baton->io_enc_mutex, NULL);
  pthread_cond_init(&baton->io_enc_cond, NULL);
  SELENE_ERR(selene_subscribe(s, SELENE_EVENT_IO_IN_ENC,
                              sln_openssl_event_cb, NULL));

  /* spawn thread */
  pthread_attr_init(&attr);
  pthread_create(&baton->thread_id, &attr, sln_openssl_io_enc_thread, s);
  pthread_attr_destroy(&attr);

  return SELENE_SUCCESS;
}

selene_error_t*
sln_openssl_threaded_destroy(selene_t *s)
{
  sln_ot_baton_t *baton = s->backend_baton;
  if (baton) {
    pthread_mutex_destroy(&baton->io_enc_mutex);
    pthread_cond_destroy(&baton->io_enc_cond);
    free(baton);
    s->backend_baton = NULL;
  }

  return SELENE_SUCCESS;
}
