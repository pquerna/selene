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
#include "sln_types.h"

#include <string.h>

/* All Certificate related configuration APIs */
selene_error_t*
selene_conf_cert_chain_add(selene_conf_t *conf, const char *certificate, const char *pkey)
{
  return SELENE_SUCCESS;
}

selene_error_t*
selene_conf_ca_trusted_cert_add(selene_conf_t *conf, const char *certificate)
{
  /* TOOD: replace with native x509 :( )*/
  BIO *bio = BIO_new(BIO_s_mem());

  int r = BIO_write(bio, certificate, strlen(certificate));
  if (r <= 0) {
    BIO_free(bio);
    return selene_error_createf(SELENE_ENOMEM, "Attempting to parse CA certificate, BIO_write returned: %d", r);
  }

  X509* x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  if (!x509) {
    BIO_free(bio);
    /* TODO: better error messages */
    return selene_error_create(SELENE_ENOMEM, "Attempting to parse CA certificate, PEM_read_bio_X509 failed.");
  }

  BIO_free(bio);

  X509_STORE_add_cert(conf->trusted_cert_store, x509);

  return SELENE_SUCCESS;
}
