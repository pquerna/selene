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

typedef struct selene_cert_t selene_cert_t;

typedef struct selene_cert_name_t {
  const char *commonName;
  const char *emailAddress;
  const char *organizationalUnitName;
  const char *organizationName;
  const char *localityName;
  const char *stateOrProvinceName;
  const char *countryName;
} selene_cert_name_t;

SELENE_API(int) selene_cert_depth(const selene_cert_t *cert);

SELENE_API(const char*) selene_cert_fingerprint_sha1(const selene_cert_t *cert);

SELENE_API(const char*) selene_cert_fingerprint_md5(const selene_cert_t *cert);

SELENE_API(int) selene_cert_not_before(const selene_cert_t *cert);

SELENE_API(int) selene_cert_not_after(const selene_cert_t *cert);

/* TODO: array of subjectAltName ?*/
/* TODO: this is a crap API */
SELENE_API(int) selene_cert_alt_names_count(const selene_cert_t *cert);

SELENE_API(const char*) selene_cert_alt_names_entry(const selene_cert_t *cert, int offset);

SELENE_API(selene_cert_name_t*) selene_cert_issuer(const selene_cert_t *cert);

SELENE_API(selene_cert_name_t*) selene_cert_subject(const selene_cert_t *cert);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _selene_cert_h_ */
