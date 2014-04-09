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

/**
 * @file selene_cert.h
 */

#include "selene_visibility.h"
#include "selene_error.h"

#ifndef _selene_cert_h_
#define _selene_cert_h_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* A single X509 certificate */
typedef struct selene_cert_t selene_cert_t;

/* A list of (related) certificates */
typedef struct selene_cert_chain_t selene_cert_chain_t;

/**
 * Common Attributes of the name in a x509 certificate.
 * Elements MAY be NULLL.
 */
typedef struct selene_cert_name_t {
  const char *commonName;
  const char *emailAddress;
  const char *organizationalUnitName;
  const char *organizationName;
  const char *localityName;
  const char *stateOrProvinceName;
  const char *countryName;
} selene_cert_name_t;

/**
 * Depth of certificate in a chain.
 */
SELENE_API(int) selene_cert_depth(selene_cert_t *cert);

/**
 * X509 version of the certificate.
 */
SELENE_API(int) selene_cert_version(selene_cert_t *cert);

/**
 * SHA1 Fingerprint of the certificate, as a : seperated string,
 * for example: "19:C3:BA:6B:1F:82:42:2A:CE:46:E0:B7:E3:0D:33:CD:53:B4:6E:52".
 */
SELENE_API(const char *) selene_cert_fingerprint_sha1(selene_cert_t *cert);

/**
 * MD5 Fingerprint of the certificate, as a : seperated string,
 * for example: "9A:A9:71:5B:98:3E:50:D7:B5:90:85:26:AB:34:27:33".
 */
SELENE_API(const char *) selene_cert_fingerprint_md5(selene_cert_t *cert);

/**
 * Converts the ASN1 time to a more human readable string, like "Dec 30 00:00:00
 * 2009 GMT".
 */
SELENE_API(const char *) selene_cert_not_before_str(selene_cert_t *cert);

/**
* Converts the ASN1 time to a more human readable string, like "Dec 30 00:00:00
* 2009 GMT".
 */
SELENE_API(const char *) selene_cert_not_after_str(selene_cert_t *cert);

/**
 * Return the ASN1 time in seconds since 1970.  Note there
 * are several possibilities for errors in this conversion,
 * since ASN1 can repersent a much larger date range.  This
 * function returns 0 on any kind of error.
 */
SELENE_API(int64_t) selene_cert_not_before(selene_cert_t *cert);

/**
 * See selene_cert_not_before.
 */
SELENE_API(int64_t) selene_cert_not_after(selene_cert_t *cert);

/**
 * Number of Subject Alt Names present in this certificate.  May return 0.
 */
SELENE_API(int) selene_cert_alt_names_count(selene_cert_t *cert);

/**
 * Read a single subject alt name. returns NULL if offset doesn't exist.
 */
SELENE_API(const char *)
    selene_cert_alt_names_entry(selene_cert_t *cert, int offset);

/**
 * Returns a {selene_cert_name_t} instance which contains describtions of the
 * Issuer for this certificate. Individual fields MAY be NULL.
 */
SELENE_API(selene_cert_name_t *) selene_cert_issuer(selene_cert_t *cert);

/**
 * Returns a {selene_cert_name_t} instance which contains describtions of the
 * Subject for this certificate. Individual fields MAY be NULL.
 */
SELENE_API(selene_cert_name_t *) selene_cert_subject(selene_cert_t *cert);

/**
 * Number of Certficates in the chain. May be 0.
 */
SELENE_API(int) selene_cert_chain_count(selene_cert_chain_t *cert);

/**
 * Returns a certificate at this offset in the chain, returns NULL if
 * the offset is invalid.
 */
SELENE_API(selene_cert_t *)
    selene_cert_chain_entry(selene_cert_chain_t *cert, int offset);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _selene_cert_h_ */
