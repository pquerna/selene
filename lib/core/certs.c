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
#include "sln_certs.h"
#include "sln_brigades.h"
#include <openssl/x509v3.h>
#include <string.h>

/**
 * This whole interface is derived on the code in Serf's SSL Buckets:
 *   <http://code.google.com/p/serf/source/browse/trunk/buckets/ssl_buckets.c>
 */

/* Copyright 2002-2004 Justin Erenkrantz and Greg Stein
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ----
 *
 * For the OpenSSL thread-safety locking code:
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
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
 *
 * Originally developed by Aaron Bannert and Justin Erenkrantz, eBuilt.
 */

selene_error_t*
sln_cert_create(selene_t *s, X509 *x509, int depth, selene_cert_t **p_cert)
{
  selene_cert_t *cert = sln_calloc(s, sizeof(selene_cert_t));

  cert->s = s;
  cert->cert = x509;
  cert->depth = depth;

  SLN_RING_ELEM_INIT(cert, link);

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

  SLN_CERT_REMOVE(cert);

  if (cert->cache_fingerprint_sha1) {
    sln_free(s, (void*)cert->cache_fingerprint_sha1);
    cert->cache_fingerprint_sha1 = NULL;
  }

  if (cert->cache_fingerprint_md5) {
    sln_free(s, (void*)cert->cache_fingerprint_md5);
    cert->cache_fingerprint_md5 = NULL;
  }

  if (cert->cache_not_before) {
    sln_free(s, (void*)cert->cache_not_before);
    cert->cache_fingerprint_md5 = NULL;
  }

  if (cert->cache_not_after) {
    sln_free(s, (void*)cert->cache_not_after);
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

  if (cert->cache_subjectAltNames) {
    sln_brigade_destroy(cert->cache_subjectAltNames);
    cert->cache_subjectAltNames = NULL;
  }

  if (cert->cert) {
    X509_free(cert->cert);
  }

  sln_free(s, cert);
}

int
selene_cert_depth(selene_cert_t *cert)
{
  return cert->depth;
}

static void
hash_to_fingerprint_hex(selene_t *s, unsigned char *md, unsigned int md_size, char **out)
{
  int i;
  const char hex[] = "0123456789ABCDEF";
  char fingerprint[EVP_MAX_MD_SIZE * 3];

  for (i=0; i<md_size; i++) {
    fingerprint[3*i] = hex[(md[i] & 0xf0) >> 4];
    fingerprint[(3*i)+1] = hex[(md[i] & 0x0f)];
    fingerprint[(3*i)+2] = ':';
  }

  if (md_size > 0) {
    fingerprint[(3*(md_size-1))+2] = '\0';
  }
  else {
    fingerprint[0] = '\0';
  }

  *out = sln_strdup(s, fingerprint);
}


static void
generate_fingerprint_sha1(selene_cert_t *cert)
{
  unsigned int md_size;
  unsigned char md[EVP_MAX_MD_SIZE];

  if (X509_digest(cert->cert, EVP_sha1(), md, &md_size)) {
    hash_to_fingerprint_hex(cert->s, md, md_size, (char **)&cert->cache_fingerprint_sha1);
  }
}

const char*
selene_cert_fingerprint_sha1(selene_cert_t *cert)
{
  if (cert->cache_fingerprint_sha1 == NULL) {
    generate_fingerprint_sha1(cert);
  }

  return cert->cache_fingerprint_sha1;
}


static void
generate_fingerprint_md5(selene_cert_t *cert)
{
  unsigned int md_size;
  unsigned char md[EVP_MAX_MD_SIZE];

  if (X509_digest(cert->cert, EVP_md5(), md, &md_size)) {
    hash_to_fingerprint_hex(cert->s, md, md_size, (char **)&cert->cache_fingerprint_md5);
  }
}

const char*
selene_cert_fingerprint_md5(selene_cert_t *cert)
{
  if (cert->cache_fingerprint_md5 == NULL) {
    generate_fingerprint_md5(cert);
  }

  return cert->cache_fingerprint_md5;
}


void
generate_expires(selene_cert_t *cert)
{
  BIO *bio;
  /* set expiry dates */
  bio = BIO_new(BIO_s_mem());

  if (bio) {
    ASN1_UTCTIME *notBefore, *notAfter;
    char buf[256];

    memset(buf, 0, sizeof (buf));

    notBefore = X509_get_notBefore(cert->cert);
    cert->cache_not_before_ts = sln_asn1_time_to_timestamp(notBefore);
    if (ASN1_TIME_print(bio, notBefore)) {
      BIO_read(bio, buf, 255);
      cert->cache_not_before = sln_strdup(cert->s, buf);
     }

     memset(buf, 0, sizeof (buf));

     notAfter = X509_get_notAfter(cert->cert);
     cert->cache_not_after_ts = sln_asn1_time_to_timestamp(notAfter);
     if (ASN1_TIME_print(bio, notAfter)) {
       BIO_read(bio, buf, 255);
       cert->cache_not_after = sln_strdup(cert->s, buf);
     }
  }

  BIO_free(bio);
}

int64_t
selene_cert_not_before(selene_cert_t *cert)
{
  if (cert->cache_not_before_ts == 0) {
    generate_expires(cert);
  }

  return cert->cache_not_before_ts;
}

int64_t
selene_cert_not_after(selene_cert_t *cert)
{
  if (cert->cache_not_after_ts == 0) {
    generate_expires(cert);
  }

  return cert->cache_not_after_ts;
}

const char*
selene_cert_not_before_str(selene_cert_t *cert)
{
  if (cert->cache_not_before == NULL) {
    generate_expires(cert);
  }

  return cert->cache_not_before;
}

const char*
selene_cert_not_after_str(selene_cert_t *cert)
{
  if (cert->cache_not_after == NULL) {
    generate_expires(cert);
  }

  return cert->cache_not_after;
}


static void
convert_X509_NAME_to_selene_name(selene_cert_t *cert, X509_NAME *org, selene_cert_name_t *name)
{
  char buf[1024];
  int ret;

  /* TODO: NULL in CN attacks */

  ret = X509_NAME_get_text_by_NID(org,
                                  NID_commonName,
                                  buf, 1024);
  if (ret != -1) {
    name->commonName = sln_strdup(cert->s, buf);
  }


  ret = X509_NAME_get_text_by_NID(org,
                                  NID_pkcs9_emailAddress,
                                  buf, 1024);

  if (ret != -1) {
    name->emailAddress = sln_strdup(cert->s, buf);
  }


  ret = X509_NAME_get_text_by_NID(org,
                                  NID_organizationName,
                                  buf, 1024);
  if (ret != -1) {
    name->organizationName = sln_strdup(cert->s, buf);
  }


  ret = X509_NAME_get_text_by_NID(org,
                                  NID_organizationalUnitName,
                                  buf, 1024);
  if (ret != -1) {
    name->organizationalUnitName = sln_strdup(cert->s, buf);
  }


  ret = X509_NAME_get_text_by_NID(org,
                                  NID_localityName,
                                  buf, 1024);
  if (ret != -1) {
    name->localityName = sln_strdup(cert->s, buf);
  }


  ret = X509_NAME_get_text_by_NID(org,
                                  NID_stateOrProvinceName,
                                  buf, 1024);
  if (ret != -1) {
    name->stateOrProvinceName = sln_strdup(cert->s, buf);
  }


  ret = X509_NAME_get_text_by_NID(org,
                                  NID_countryName,
                                  buf, 1024);
  if (ret != -1) {
    name->countryName = sln_strdup(cert->s, buf);
  }

}


static void
generate_issuer(selene_cert_t *cert)
{
  X509_NAME *issuer = X509_get_issuer_name(cert->cert);
  if (!issuer) {
    /* Is it better to make an empty cache_subject with NULL fields, or just leave it NULL? */
    return;
  }

  cert->cache_issuer = sln_calloc(cert->s, sizeof(selene_cert_name_t));

  convert_X509_NAME_to_selene_name(cert, issuer, cert->cache_issuer);
}

selene_cert_name_t*
selene_cert_issuer(selene_cert_t *cert)
{
  if (cert->cache_issuer == NULL) {
    generate_issuer(cert);
  }
  return cert->cache_issuer;
}


static void
generate_subject(selene_cert_t *cert)
{
  X509_NAME *subject = X509_get_subject_name(cert->cert);
  if (!subject) {
    /* Is it better to make an empty cache_subject with NULL fields, or just leave it NULL? */
    return;
  }

  cert->cache_subject = sln_calloc(cert->s, sizeof(selene_cert_name_t));

  convert_X509_NAME_to_selene_name(cert, subject, cert->cache_subject);
}

selene_cert_name_t*
selene_cert_subject(selene_cert_t *cert)
{
  if (cert->cache_subject == NULL) {
    generate_subject(cert);
  }
  return cert->cache_subject;
}


int
selene_cert_version(selene_cert_t *cert)
{
  /* This returns the value, which... starts at 0, so version 3 is actually 2 here, bump it. */
  return X509_get_version(cert->cert) + 1;
}




static void
generate_subject_alt_names(selene_cert_t *cert)
{
  STACK_OF(GENERAL_NAME) *names;

  /* TODO: err */
  sln_brigade_create(cert->s->alloc, &cert->cache_subjectAltNames);

  /* Get subjectAltNames */
  names = X509_get_ext_d2i(cert->cert, NID_subject_alt_name, NULL, NULL);
  if (names) {
    int i;
    int names_count = sk_GENERAL_NAME_num(names);

    for (i = 0; i < names_count; i++) {
      sln_bucket_t *e = NULL;
      GENERAL_NAME *nm = sk_GENERAL_NAME_value(names, i);

      switch (nm->type) {
      case GEN_DNS:
        sln_bucket_create_copy_bytes(cert->s->alloc, &e, (const char*)nm->d.ia5->data,  nm->d.ia5->length);
        SLN_BRIGADE_INSERT_TAIL(cert->cache_subjectAltNames, e);
        break;
      default:
        /* Don't know what to do - skip. */
        break;
      }
    }

    sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
  }
}

int
selene_cert_alt_names_count(selene_cert_t *cert)
{
  if (cert->cache_subjectAltNames == NULL) {
    generate_subject_alt_names(cert);
  }

  return sln_brigade_bucket_count(cert->cache_subjectAltNames);
}

const char*
selene_cert_alt_names_entry(selene_cert_t *cert, int offset)
{
  int i = 0;
  sln_bucket_t *b;

  if (cert->cache_subjectAltNames == NULL) {
    generate_subject_alt_names(cert);
  }

  SLN_RING_FOREACH(b, &(cert->cache_subjectAltNames)->list, sln_bucket_t, link)
  {
    if (offset == i) {
      return b->data;
    }

    if (i > offset) {
      break;
    }

    i++;
  }

  return NULL;
}

selene_error_t*
sln_cert_chain_create(selene_t *s, selene_cert_chain_t **out_cc)
{
  selene_cert_chain_t* cc = sln_calloc(s, sizeof(selene_cert_chain_t));

  SLN_RING_INIT(&cc->list, selene_cert_t, link);

  *out_cc = cc;

  return SELENE_SUCCESS;
}

int
selene_cert_chain_count(selene_cert_chain_t *cc)
{
  int i = 0;
  selene_cert_t *c;

  SLN_RING_FOREACH(c, &(cc)->list, selene_cert_t, link)
  {
    i++;
  }

  return i;
}

void
sln_cert_chain_destroy(selene_t *s, selene_cert_chain_t *chain)
{
  sln_cert_chain_clear(s, chain);
  sln_free(s, chain);
}

void
sln_cert_chain_clear(selene_t *s, selene_cert_chain_t *chain)
{
  selene_cert_t *c;

  while (!SLN_CERT_CHAIN_EMPTY(chain)) {
      c = SLN_CERT_CHAIN_FIRST(chain);
      sln_cert_destroy(c);
  }
}

selene_cert_t*
selene_cert_chain_entry(selene_cert_chain_t *cc, int offset)
{
  int i = 0;
  selene_cert_t *c;

  SLN_RING_FOREACH(c, &(cc)->list, selene_cert_t, link)
  {
    if (offset == i) {
      return c;
    }

    if (i > offset) {
      break;
    }

    i++;
  }

  return NULL;
}
