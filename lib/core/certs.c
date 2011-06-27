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
#include "selene_cert.h"
#include "sln_types.h"

selene_error_t*
sln_cert_create(selene_t *s, X509 *x509, int depth, selene_cert_t **p_cert)
{
  selene_cert_t *cert = sln_calloc(s, sizeof(selene_cert_t));

  cert->s = s;
  cert->cert = x509;
  cert->depth = depth;

  *p_cert = cert;
  return SELENE_SUCCESS;
}

static void
sln_cert_name_destroy(selene_t *s, selene_cert_name_t *cn)
{
  if (cn->commonName) {
    sln_free(s, (void*)cn->commonName);
    cn->commonName = NULL;
  }

  if (cn->emailAddress) {
    sln_free(s, (void*)cn->emailAddress);
    cn->emailAddress = NULL;
  }

  if (cn->organizationalUnitName) {
    sln_free(s, (void*)cn->organizationalUnitName);
    cn->organizationalUnitName = NULL;
  }

  if (cn->organizationName) {
    sln_free(s, (void*)cn->organizationName);
    cn->organizationName = NULL;
  }

  if (cn->localityName) {
    sln_free(s, (void*)cn->localityName);
    cn->localityName = NULL;
  }

  if (cn->stateOrProvinceName) {
    sln_free(s, (void*)cn->stateOrProvinceName);
    cn->stateOrProvinceName = NULL;
  }

  if (cn->countryName) {
    sln_free(s, (void*)cn->countryName);
    cn->countryName = NULL;
  }

  sln_free(s, cn);
}

void
sln_cert_destroy(selene_cert_t *cert)
{
  selene_t *s = cert->s;

  if (cert->cache_fingerprint_sha1) {
    sln_free(s, (void*)cert->cache_fingerprint_sha1);
    cert->cache_fingerprint_sha1 = NULL;
  }

  if (cert->cache_fingerprint_md5) {
    sln_free(s, (void*)cert->cache_fingerprint_md5);
    cert->cache_fingerprint_md5 = NULL;
  }

  if (cert->cache_subject) {
    sln_cert_name_destroy(s, cert->cache_subject);
    cert->cache_subject = NULL;
  }

  if (cert->cache_issuer) {
    sln_cert_name_destroy(s, cert->cache_issuer);
    cert->cache_issuer = NULL;
  }

  sln_free(s, cert);
}

int
selene_cert_depth(const selene_cert_t *cert)
{
  return cert->depth;
}

const char*
selene_cert_fingerprint_sha1(const selene_cert_t *cert)
{
  return cert->cache_fingerprint_sha1;
}

const char*
selene_cert_fingerprint_md5(const selene_cert_t *cert)
{
  return cert->cache_fingerprint_md5;
}

int
selene_cert_not_before(const selene_cert_t *cert)
{
  return cert->cache_not_before;
}

int
selene_cert_not_after(const selene_cert_t *cert)
{
  return cert->cache_not_after;
}

int
selene_cert_alt_names_count(const selene_cert_t *cert)
{
  return cert->cache_alt_names_len;
}

const char*
selene_cert_alt_names_entry(const selene_cert_t *cert, int offset)
{
  return NULL;
}

selene_cert_name_t*
selene_cert_issuer(const selene_cert_t *cert)
{
  return cert->cache_issuer;
}

selene_cert_name_t*
selene_cert_subject(const selene_cert_t *cert)
{
  return cert->cache_subject;
}
