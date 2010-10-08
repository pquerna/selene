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
#include <unistd.h>
#include <assert.h>

static void
handle_ssl_rv(sln_ot_baton_t *baton, int rv, const char *func)
{
  int err;
  err = SSL_get_error(baton->ssl, rv);
  if (err != SSL_ERROR_WANT_WRITE &&
      err != SSL_ERROR_WANT_READ) {
    char buf[512];
    /* TODO: look at ssl error queue */
    ERR_error_string_n(ERR_get_error(), &buf[0], sizeof(buf));
    baton->err = selene_error_createf(SELENE_EINVAL, "%s failed: (%d) %s", func, err, buf);
    baton->should_exit = 1;
  }
  else {
    baton->want = err;
  }
}

static selene_error_t*
sln_ot_mtio_cb(selene_t *s, void *baton_)
{
  /* Always invoked holding the lock */
  sln_ot_baton_t *baton = baton_;

  if (!SLN_BRIGADE_EMPTY(baton->bb.out_enc)) {
    SLN_BRIGADE_CONCAT(s->bb.out_enc, baton->bb.out_enc);
    SELENE_ERR(selene_publish(s, SELENE_EVENT_IO_OUT_ENC));
  }

  if (!SLN_BRIGADE_EMPTY(baton->bb.out_cleartext)) {
    SLN_BRIGADE_CONCAT(s->bb.out_cleartext, baton->bb.out_cleartext);
    SELENE_ERR(selene_publish(s, SELENE_EVENT_IO_OUT_CLEAR));
  }

  return SELENE_SUCCESS;
}

/* Converts a selene enum of ciphers to OpenSSL */
void*
sln_ot_io_thread(void *thread_baton)
{
  char buf[4096];
  int rv = 0;
  int need_mt_io = 0;
  selene_t *s = (selene_t*) thread_baton;
  sln_ot_baton_t *baton = s->backend_baton;
  sln_bucket_t *b;
  sln_bucket_t *e;
  sln_bucket_t *bit;
  SLN_ASSERT_CONTEXT(s);

  slnDbg(s, "(openssl) thread start");

  SSL_do_handshake(baton->ssl);
  do {
    need_mt_io = 0;
    /* wait then process incoming data */

    slnDbg(s, "(openssl) loop start");

    pthread_mutex_lock(&(baton)->mutex);
#if 0
     if (!SSL_is_init_finished(baton->ssl)) {
      if (s->conf.mode == SLN_MODE_CLIENT) {
        slnDbg(s, "(openssl) SSL_connect");
        rv = SSL_connect(baton->ssl);
      }
      else {
        /* TOOD: finish server support */
        slnDbg(s, "(openssl) SSL_accept");
        rv = SSL_accept(baton->ssl);
      }

      if (rv == 1) {
        /* Finished */
        slnInfo(s, "Handshake complete");
      }
      else {
        handle_ssl_rv(baton, rv, "SSL_accept");
        if (baton->should_exit) {
          break;
        }
      }
    }
#endif

    do {
      slnDbg(s, "(openssl) trying to read cleartext");
      rv = SSL_read(baton->ssl, &buf[0], sizeof(buf));
      if (rv > 0) {
        slnDbg(s, "(openssl) SSL_read result = %d bytes", rv);
        sln_bucket_create_copy_bytes(&e, &buf[0], rv);
        buf[rv] = '\0';
        slnDbg(s, "data= %s", &buf[0]);
        SLN_BRIGADE_INSERT_TAIL(baton->bb.out_cleartext, e);
        need_mt_io = 1;
      }
      else {
        handle_ssl_rv(baton, rv, "SSL_read");
        break;
      }
    } while (1);

    SLN_RING_FOREACH_SAFE(b, bit, &(baton->bb.in_cleartext)->list, sln_bucket_t, link)
    {
      SLN_RING_REMOVE(b, link);
      slnDbg(s, "(openssl) sending clear %zd bytes", b->size);
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

    do {
      rv = BIO_read(baton->bio_write, &buf[0], sizeof(buf));
      if (rv > 0) {
        slnDbg(s, "(openssl) sending enc %d bytes", rv);
        assert(sln_bucket_create_copy_bytes(&e, &buf[0], rv) == SELENE_SUCCESS);
        SLN_BRIGADE_INSERT_TAIL((baton->bb.out_enc), e);
        need_mt_io = 1;
      }
      else {
        handle_ssl_rv(baton, rv, "BIO_read");
        break;
      }
    } while (1);

    SLN_RING_FOREACH_SAFE(b, bit, &(baton->bb.in_enc)->list, sln_bucket_t, link)
    {
      SLN_RING_REMOVE(b, link);
      slnDbg(s, "(openssl) input enc %zd bytes", b->size);
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

    if (need_mt_io) {
      /* TOOD: queue main thread io callback */
      sln_xthread_cb_t *cbt = calloc(1, sizeof(sln_xthread_cb_t));
      cbt->cb = sln_ot_mtio_cb;
      cbt->baton = baton;
      SLN_XT_INSERT_TAIL(baton->main, cbt);
    }

    slnDbg(s, "baton->want = %d", baton->want);

    if (baton->want != 0 || !SLN_XT_EMPTY(&baton->main)) {

    }

    pthread_mutex_unlock(&(baton)->mutex);

    if (baton->should_exit) {
      break;
    }

    sleep(1);
  } while (baton->should_exit == 0);

  if (baton->err) {
    slnDbg(s, "OPENSSL EXITING: (%d) %s [%s:%d]", baton->err->err, baton->err->msg, baton->err->file, baton->err->line);
  }
  return NULL;
}

selene_error_t*
sln_ot_event_cycle(selene_t *s)
{
  selene_error_t* err;
  sln_xthread_cb_t *cb;
  sln_xthread_cb_t *cbit;
  sln_ot_baton_t *baton = s->backend_baton;

  do {
    pthread_mutex_lock(&baton->mutex);
    SLN_RING_FOREACH_SAFE(cb, cbit, &(baton)->main, sln_xthread_cb_t, link)
    {
      SLN_RING_REMOVE(cb, link);
      err = cb->cb(s, cb->baton);
      free(cb);
      if (err) {
        pthread_mutex_unlock(&baton->mutex);
        return err;
      }
    }

    if (baton->want != 0) {
      pthread_mutex_unlock(&baton->mutex);
      break;
    }
    pthread_mutex_unlock(&baton->mutex);
  } while(1);

  return SELENE_SUCCESS;
}

selene_error_t*
sln_ot_event_cb(selene_t *s, selene_event_e event, void *unused_baton)
{
  sln_ot_baton_t *baton = s->backend_baton;

  SLN_ASSERT_CONTEXT(s);

  switch (event) {
  case SELENE_EVENT_IO_IN_ENC:
  case SELENE_EVENT_IO_IN_CLEAR:
    pthread_mutex_lock(&baton->mutex);
    SLN_BRIGADE_CONCAT(baton->bb.in_cleartext, s->bb.in_cleartext);
    SLN_BRIGADE_CONCAT(baton->bb.in_enc, s->bb.in_enc);
    pthread_mutex_unlock(&baton->mutex);

    slnDbg(s, "(openssl) sln_ot_event_cb, sent data to thread, going to event cycle");

    SELENE_ERR(sln_ot_event_cycle(s));
    break;
  default:
    return selene_error_createf(SELENE_EINVAL,
                                "captured backend event %d without handler",
                                event);
  }

  return SELENE_SUCCESS;
}
