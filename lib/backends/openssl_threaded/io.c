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

#include "openssl_threaded.h"

/* Converts a selene enum of ciphers to OpenSSL */
void*
sln_ot_io_thread(void *thread_baton)
{
  int err = 0;
  int rv = 0;
  selene_t *s = (selene_t*) thread_baton;
  sln_ot_baton_t *baton = s->backend_baton;
  sln_bucket_t *b;
  sln_bucket_t *bit;
  SLN_ASSERT_CONTEXT(s);

  if (s->conf.mode == SLN_MODE_CLIENT) {
    rv = SSL_connect(baton->ssl);
  }
  else {
    /* TOOD: finish server support */
    rv = SSL_accept(baton->ssl);
  }

  if (rv == 1) {
    /* Finished */
  }
  else {
    err = SSL_get_error(baton->ssl, rv);
    if (err != SSL_ERROR_WANT_WRITE &&
        err != SSL_ERROR_WANT_READ) {
      /* TODO: look at ssl error queue */
      baton->err = selene_error_createf(SELENE_EINVAL, "SSL_connect failed: (%d)", err);
      baton->should_exit = 1;
      goto cleanup;
    }
    else {
      baton->want = err;
      /* TODO: insert want callback */
    }
  }

  do {
    /* wait then process incoming data */
    pthread_mutex_lock(&(baton)->mutex);
    if (baton->should_exit == 0) {
      pthread_cond_wait(&(baton)->cond, &(baton)->mutex);
    }

    if (baton->should_exit == 0) {
      SLN_RING_FOREACH_SAFE(b, bit, &(s)->bb_in_enc->list, sln_bucket_t, link)
      {
        SLN_RING_REMOVE(b, link);
      }
    }

    pthread_mutex_unlock(&(baton)->mutex);

  } while (baton->should_exit == 0);

cleanup:
  SSL_CTX_free(baton->ctx);
  SSL_free(baton->ssl);
  return NULL;
}

selene_error_t*
sln_ot_event_cb(selene_t *s, selene_event_e event, void *unused_baton)
{
  selene_error_t* err;
  sln_mainthread_cb_t *cb;
  sln_mainthread_cb_t *cbit;

  SLN_ASSERT_CONTEXT(s);
  sln_ot_baton_t *baton = s->backend_baton;

  switch (event) {
  case SELENE_EVENT_IO_IN_ENC:
  case SELENE_EVENT_IO_IN_CLEAR:
    pthread_mutex_lock(&baton->mutex);
    pthread_cond_signal(&baton->cond);
    pthread_mutex_unlock(&baton->mutex);

    pthread_cond_wait(&(baton)->cond, &(baton)->mutex);
    SLN_RING_FOREACH_SAFE(cb, cbit, &(baton)->list, sln_mainthread_cb_t, link)
    {
      SLN_RING_REMOVE(cb, link);
      err = cb->cb(s, cb->baton);
      if (err) {
        return err;
      }
      free(cb);
    }
    pthread_mutex_unlock(&baton->mutex);
    break;
  default:
    return selene_error_createf(SELENE_EINVAL,
                                "captured backend event %d without handler",
                                event);
  }

  return SELENE_SUCCESS;
}
