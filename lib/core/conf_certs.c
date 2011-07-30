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
#include "selene_trusted_ca_certificates.h"
#include "sln_certs.h"
#include "sln_arrays.h"

#include <openssl/err.h>

#include <string.h>

/* All Certificate related configuration APIs */

/* Based on Node's SSL_CTX_use_certificate_chain, in src/node_crypto.cc */
selene_error_t*
read_certificate_chain(selene_conf_t *conf, BIO *in, selene_cert_chain_t** p_certs) {
  X509 *x = NULL;
  selene_cert_chain_t* chain;
  selene_cert_t *tmpc;

  x = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);

  if (x == NULL) {
    return selene_error_create(SELENE_ENOMEM, "Failed to parse certificate");
  }

  SELENE_ERR(sln_cert_chain_create(conf, &chain));
  SELENE_ERR(sln_cert_create(conf, x, 0, &tmpc));
  SLN_CERT_CHAIN_INSERT_TAIL(chain, tmpc);

  {
    // If we could set up our certificate, now proceed to
    // the CA certificates.
    X509 *ca;
    unsigned long err;

    while ((ca = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
      SELENE_ERR(sln_cert_create(conf, ca, 0, &tmpc));
      SLN_CERT_CHAIN_INSERT_TAIL(chain, tmpc);
    }

    // When the while loop ends, it's usually just EOF.
    err = ERR_peek_last_error();
    if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
        ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
      ERR_clear_error();
    } else  {
      // some real error
      /* TODO: handle parse errors of the ca certs */
    }
  }

  *p_certs = chain;

  return SELENE_SUCCESS;
}

selene_error_t*
selene_conf_cert_chain_add(selene_conf_t *conf, const char *certificate, const char *pkey)
{
  selene_cert_chain_t *certs = NULL;
  BIO *bio = BIO_new(BIO_s_mem());

  int r = BIO_write(bio, certificate, strlen(certificate));
  if (r <= 0) {
    BIO_free(bio);
    return selene_error_createf(SELENE_ENOMEM, "Attempting to parse Cert Chain certificate, BIO_write returned: %d", r);
  }

  /* TODO: private key */
  SELENE_ERR(read_certificate_chain(conf, bio, &certs));

  SLN_ARRAY_PUSH(conf->certs, selene_cert_chain_t*) = certs;

  return SELENE_SUCCESS;
}

selene_error_t*
selene_conf_ca_trusted_cert_add(selene_conf_t *conf, const char *certificate)
{
  /* TOOD: replace with native x509 :( ) */
  X509* x509;
  BIO *bio = BIO_new(BIO_s_mem());

  int r = BIO_write(bio, certificate, strlen(certificate));
  if (r <= 0) {
    BIO_free(bio);
    return selene_error_createf(SELENE_ENOMEM, "Attempting to parse CA certificate, BIO_write returned: %d", r);
  }

  x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  if (!x509) {
    BIO_free(bio);
    /* TODO: better error messages */
    return selene_error_create(SELENE_ENOMEM, "Attempting to parse CA certificate, PEM_read_bio_X509 failed.");
  }

  BIO_free(bio);

  X509_STORE_add_cert(conf->trusted_cert_store, x509);

  return SELENE_SUCCESS;
}
