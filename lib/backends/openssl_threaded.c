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

#include <openssl/ssl.h>
#include <openssl/err.h>

selene_error_t*
sln_openssl_threaded_initilize()
{
  /* TODO: is this correct? */
  // CRYPTO_malloc_init();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  OpenSSL_add_all_algorithms();

  /* TOOD: Crytpo Mutex init? */

  return SELENE_SUCCESS;
}

void
sln_openssl_threaded_terminate()
{
  ERR_free_strings();
  CRYPTO_cleanup_all_ex_data();
}

typedef struct sln_mainthread_cb_t sln_mainthread_cb_t;

struct sln_mainthread_cb_t {
  SLN_RING_ENTRY(sln_mainthread_cb_t) link;
  sln_standard_baton_cb *cb;
  void *baton;
};

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
} sln_ot_baton_t;

/* Converts a selene enum of ciphers to OpenSSL */
static char* sln_ciphers_to_openssl(int selene_ciphers)
{
  /* TODO: find a better max for cipher counts */
  const char *argv[32] = {0};
  int i = 0;
  int j = 0;
  size_t size = 0;

  if (selene_ciphers & SELENE_CS_RSA_WITH_RC4_128_SHA) {
    argv[i] = "RC4-SHA:";
    size += strlen(argv[i++]);
  }

  if (selene_ciphers & SELENE_CS_RSA_WITH_AES_128_CBC_SHA) {
    argv[i] = "AES128-SHA:";
    size += strlen(argv[i++]);
  }

  if (selene_ciphers & SELENE_CS_RSA_WITH_AES_256_CBC_SHA) {
    argv[i] = "AES256-SHA:";
    size += strlen(argv[i++]);
  }

  if (i == 0) {
    return NULL;
  }

  char *out = malloc(size + 1);
  size_t off = 0;

  for (j = 0; j < i; j++) {
    size_t l = strlen(argv[j]);
    memcpy(out+off, argv[j], l);
    off += l;
  }

  out[off-1] = '\0';

  return out;
}

static void*
sln_openssl_io_thread(void *thread_baton)
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

static selene_error_t*
sln_openssl_event_cb(selene_t *s, selene_event_e event, void *unused_baton)
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

selene_error_t*
sln_openssl_threaded_create(selene_t *s)
{
  sln_ot_baton_t *baton;
  SLN_ASSERT_CONTEXT(s);

  baton = (sln_ot_baton_t*) calloc(1, sizeof(*baton));
  s->backend_baton = baton;

  /* Setup all the OpenSSL context stuff*/
  if (s->conf.mode == SLN_MODE_CLIENT) {
    baton->meth = SSLv23_client_method();
  }
  else {
    baton->meth = SSLv23_server_method();
  }

  baton->ctx = SSL_CTX_new(baton->meth);

  SLN_RING_INIT(&baton->list, sln_mainthread_cb_t, link);

  return SELENE_SUCCESS;
}

selene_error_t*
sln_openssl_threaded_start(selene_t *s)
{
  sln_ot_baton_t *baton = s->backend_baton;
  SLN_ASSERT_CONTEXT(s);

  pthread_attr_t attr;

  char *str = sln_ciphers_to_openssl(s->conf.ciphers);

  if (str == NULL) {
    return selene_error_create(SELENE_EINVAL,
                               "No ciphers available in openssl threaded backend.");
  }
  else {
    int rv = SSL_CTX_set_cipher_list(baton->ctx, str);
    free(str);
    if (rv == 0) {
      return selene_error_create(SELENE_EINVAL,
                                 "Unable to set ciphers in openssl threaded");
    }
  }

  /* We never want to let anyone use SSL v2. */
  SSL_CTX_set_options(baton->ctx, SSL_OP_NO_SSLv2);

  if (!(s->conf.protocols & SELENE_PROTOCOL_SSL30)) {
    SSL_CTX_set_options(baton->ctx, SSL_OP_NO_SSLv3);
  }

  if (!(s->conf.protocols & SELENE_PROTOCOL_TLS10)) {
    SSL_CTX_set_options(baton->ctx, SSL_OP_NO_TLSv1);
  }

  if (!(s->conf.protocols & SELENE_PROTOCOL_TLS10) &&
      !(s->conf.protocols & SELENE_PROTOCOL_SSL30)) {
    return selene_error_create(SELENE_EINVAL,
                               "TLS 1.0 or SSL 3.0 must be enabled when "
                               "using the OpenSSL Threaded backend.");
  }

  /* subscribe to events */
  SELENE_ERR(selene_subscribe(s, SELENE_EVENT_IO_IN_ENC,
                              sln_openssl_event_cb, NULL));

  SELENE_ERR(selene_subscribe(s, SELENE_EVENT_IO_IN_CLEAR,
                              sln_openssl_event_cb, NULL));

  /* TODO: write custom BIO handlers that use buckets natively,
   * eliminating extra memcpys; See mod_ssl for an example
   */
  baton->ssl = SSL_new(baton->ctx);
  baton->bio_read = BIO_new(BIO_s_mem());
  baton->bio_write = BIO_new(BIO_s_mem());

  SSL_set_bio(baton->ssl, baton->bio_read, baton->bio_write);

  /* spawn thread */
  pthread_mutex_init(&baton->mutex, NULL);
  pthread_cond_init(&baton->cond, NULL);
  pthread_attr_init(&attr);
  pthread_create(&baton->thread_id, &attr, sln_openssl_io_thread, s);
  pthread_attr_destroy(&attr);

  return SELENE_SUCCESS;
}

selene_error_t*
sln_openssl_threaded_destroy(selene_t *s)
{
  sln_ot_baton_t *baton = s->backend_baton;
  if (baton) {
    pthread_mutex_lock(&baton->mutex);
    baton->should_exit = 1;
    pthread_cond_broadcast(&baton->cond);
    pthread_mutex_unlock(&baton->mutex);
    pthread_join(baton->thread_id, NULL);
    pthread_mutex_destroy(&baton->mutex);
    pthread_cond_destroy(&baton->cond);
    free(baton);
    s->backend_baton = NULL;
  }

  return SELENE_SUCCESS;
}
