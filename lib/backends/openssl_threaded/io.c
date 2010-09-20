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
#include "sln_brigades.h"

static void
handle_ssl_rv(sln_ot_baton_t *baton, int rv, const char *func)
{
  int err;
  err = SSL_get_error(baton->ssl, rv);
  if (err != SSL_ERROR_WANT_WRITE &&
      err != SSL_ERROR_WANT_READ) {
    /* TODO: look at ssl error queue */
    baton->err = selene_error_createf(SELENE_EINVAL, "%s failed: (%d)", func, err);
    baton->should_exit = 1;
  }
  else {
    baton->want = err;
  }
}

/* Converts a selene enum of ciphers to OpenSSL */
void*
sln_ot_io_thread(void *thread_baton)
{
  int rv = 0;
  selene_t *s = (selene_t*) thread_baton;
  sln_ot_baton_t *baton = s->backend_baton;
  sln_bucket_t *b;
  sln_bucket_t *e;
  sln_bucket_t *bit;
  SLN_ASSERT_CONTEXT(s);

  do {
    if (!SSL_is_init_finished(baton->ssl)) {
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
        handle_ssl_rv(baton, rv, "SSL_accept");
      }
    }
    else {
      /* wait then process incoming data */
      pthread_mutex_lock(&(baton)->mutex);

      if (baton->should_exit == 0) {
        pthread_cond_wait(&(baton)->cond, &(baton)->mutex);
      }

      if (baton->should_exit == 0) {
        SLN_RING_FOREACH_SAFE(b, bit, &(baton->bb.in_enc)->list, sln_bucket_t, link)
        {
          SLN_RING_REMOVE(b, link);
          rv = BIO_write(baton->bio_read, b->data, b->size);
          if (rv > 0) {
            if (rv != b->size) {
              /* underflow */
              sln_bucket_create_copy_bytes(&e, b->data + rv, b->size - rv);
              SLN_BRIGADE_INSERT_HEAD(baton->bb.in_enc, e);
            }
            sln_bucket_destroy(b);
          }
          else {
            SLN_BRIGADE_INSERT_HEAD(baton->bb.in_enc, b);
            /* TODO: ugh, log this? BIO fail? */
            break;
          }
        }

        SLN_RING_FOREACH_SAFE(b, bit, &(baton->bb.in_cleartext)->list, sln_bucket_t, link)
        {
          SLN_RING_REMOVE(b, link);
          rv = SSL_write(baton->ssl, b->data, b->size);
          if (rv > 0) {
            if (rv != b->size) {
              /* underflow */
              sln_bucket_create_copy_bytes(&e, b->data + rv, b->size - rv);
              SLN_BRIGADE_INSERT_HEAD(baton->bb.in_cleartext, e);
            }
            sln_bucket_destroy(b);
          }
          else {
            /* beeep beeeeeep beeeeeep back that freight truck up */
            SLN_BRIGADE_INSERT_HEAD(baton->bb.in_cleartext, b);
            handle_ssl_rv(baton, rv, "SSL_write");
          }
        }
      }
      pthread_mutex_unlock(&(baton)->mutex);
    }
  } while (baton->should_exit == 0);

  /* TODO: this is definately leaking memory, FIXME */
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
  sln_ot_baton_t *baton = s->backend_baton;

  SLN_ASSERT_CONTEXT(s);

  switch (event) {
  case SELENE_EVENT_IO_IN_ENC:
  case SELENE_EVENT_IO_IN_CLEAR:
    pthread_mutex_lock(&baton->mutex);
    SLN_BRIGADE_CONCAT(baton->bb.in_cleartext, s->bb.in_cleartext);
    SLN_BRIGADE_CONCAT(baton->bb.in_enc, s->bb.in_enc);
    pthread_cond_signal(&baton->cond);
    pthread_mutex_unlock(&baton->mutex);

    pthread_cond_wait(&(baton)->cond, &(baton)->mutex);
    SLN_RING_FOREACH_SAFE(cb, cbit, &(baton)->list, sln_mainthread_cb_t, link)
    {
      SLN_RING_REMOVE(cb, link);
      err = cb->cb(s, cb->baton);
      free(cb);
      if (err) {
        return err;
      }
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
