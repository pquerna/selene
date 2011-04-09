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

#ifdef WANT_OPENSSL_THREADED

#ifdef WANT_PTHREADS
static pthread_mutex_t lock[CRYPTO_NUM_LOCKS];

static unsigned long
sln_pthreads_thread_id()
{
  return (unsigned long) pthread_self();
}

static void
sln_pthreads_locking_callback(int mode, int type, char *file, int line)
{
  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(lock[type]));
  }
  else {
    pthread_mutex_unlock(&(lock[type]));
  }
}

static void
sln_pthreads_init()
{
  int i;
  memset(&lock, 0, sizeof(lock));
  for (i=0; i<CRYPTO_NUM_LOCKS; i++) {
    pthread_mutex_init(&lock[i], NULL);
  }
  CRYPTO_set_id_callback((unsigned long (*)())sln_pthreads_thread_id);
  CRYPTO_set_locking_callback((void (*)())sln_pthreads_locking_callback);
}

static void
sln_pthreads_destroy()
{
  int i;
  CRYPTO_set_locking_callback(NULL);
  for (i=0; i<CRYPTO_NUM_LOCKS; i++) {
    pthread_mutex_destroy(&lock[i]);
  }
}
#endif

selene_error_t*
sln_ot_initilize()
{
  /* TODO: is this correct? */
  // CRYPTO_malloc_init();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  OpenSSL_add_all_algorithms();

  /* TODO: Crypto Mutex init? */
#ifdef WANT_PTHREADS
  sln_pthreads_init();
#else
#error no locking library defined
#endif

  return SELENE_SUCCESS;
}

void
sln_ot_terminate()
{
#ifdef WANT_PTHREADS
  sln_pthreads_destroy();
#endif
  ERR_free_strings();
  CRYPTO_cleanup_all_ex_data();
}

selene_error_t*
sln_ot_create(selene_t *s)
{
  sln_ot_baton_t *baton;
  SLN_ASSERT_CONTEXT(s);

  baton = (sln_ot_baton_t*) calloc(1, sizeof(*baton));
  s->backend_baton = baton;

  SLN_RING_INIT(&baton->main, sln_xthread_cb_t, link);
  SLN_RING_INIT(&baton->worker, sln_xthread_cb_t, link);

  /* Setup all the OpenSSL context stuff*/
  if (s->mode == SLN_MODE_CLIENT) {
//    baton->meth = SSLv23_client_method();
    baton->meth = TLSv1_client_method();
  }
  else {
    baton->meth = SSLv23_server_method();
  }

  baton->ctx = SSL_CTX_new(baton->meth);

  return SELENE_SUCCESS;
}

static int
validate_server_cert(int cert_valid, X509_STORE_CTX *store_ctx)
{
  /* TODO: rewrite */
  return 1;
}

selene_error_t*
sln_ot_start(selene_t *s)
{
  sln_ot_baton_t *baton = s->backend_baton;
  SLN_ASSERT_CONTEXT(s);

  pthread_attr_t attr;

  char *str = sln_ot_ciphers_to_openssl(s->conf->ciphers);

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


  SSL_CTX_set_verify(baton->ctx, SSL_VERIFY_PEER,
                     validate_server_cert);

  /* Enable bug compat mode... */
  SSL_CTX_set_options(baton->ctx, SSL_OP_ALL);

  /* We never want to let anyone use SSL v2. */
  slnDbg(s, "openssl: disabled ssl 2.0: %d", s->conf->protocols);
  SSL_CTX_set_options(baton->ctx, SSL_OP_NO_SSLv2);

  if (!(s->conf->protocols & SELENE_PROTOCOL_SSL30)) {
    slnDbg(s, "openssl: enabling ssl 3.0");
    SSL_CTX_set_options(baton->ctx, SSL_OP_NO_SSLv3);
  }

  if (!(s->conf->protocols & SELENE_PROTOCOL_TLS10)) {
    SSL_CTX_set_options(baton->ctx, SSL_OP_NO_TLSv1);
  }

  if (!(s->conf->protocols & SELENE_PROTOCOL_TLS10) &&
      !(s->conf->protocols & SELENE_PROTOCOL_SSL30)) {
    return selene_error_create(SELENE_EINVAL,
                               "TLS 1.0 or SSL 3.0 must be enabled when "
                               "using the OpenSSL Threaded backend.");
  }

  SELENE_ERR(sln_iobb_create(&baton->bb));

  /* subscribe to events */
  SELENE_ERR(selene_subscribe(s, SELENE_EVENT_IO_IN_ENC,
                              sln_ot_event_cb, NULL));

  SELENE_ERR(selene_subscribe(s, SELENE_EVENT_IO_IN_CLEAR,
                              sln_ot_event_cb, NULL));

  /* TODO: write custom BIO handlers that use buckets natively,
   * eliminating extra memcpys; See mod_ssl for an example
   */
  baton->ssl = SSL_new(baton->ctx);
  baton->bio_read = BIO_new(BIO_s_mem());
  baton->bio_write = BIO_new(BIO_s_mem());

  SSL_set_bio(baton->ssl, baton->bio_read, baton->bio_write);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
  if (s->conf->sni != NULL) {
    SSL_set_tlsext_host_name(baton->ssl, s->conf->sni);
  }
#endif

  SSL_set_connect_state(baton->ssl);

  /* spawn thread */
  pthread_mutex_init(&baton->mutex, NULL);
  pthread_cond_init(&baton->cond, NULL);

  pthread_attr_init(&attr);
  pthread_create(&baton->thread_id, &attr, sln_ot_io_thread, s);
  pthread_attr_destroy(&attr);

  SELENE_ERR(sln_ot_event_cycle(s));

  return SELENE_SUCCESS;
}

selene_error_t*
sln_ot_destroy(selene_t *s)
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

    /* TODO: this is definately leaking memory, FIXME */
    SSL_CTX_free(baton->ctx);
    SSL_free(baton->ssl);

    free(baton);
    s->backend_baton = NULL;
  }

  return SELENE_SUCCESS;
}

#endif /* WANT_OPENSSL_THREADED */
