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

#ifndef _sln_digest_h_
#define _sln_digest_h_

#ifdef SLN_HAVE_OSX_COMMONCRYPTO
selene_error_t* sln_digest_osx_cc_create(selene_t *s, sln_digest_e type, sln_digest_t **p_digest);
void sln_digest_osx_cc_update(sln_digest_t *digest, const void *data, size_t len);
void sln_digest_osx_cc_final(sln_digest_t *digest, unsigned char *md);
void sln_digest_osx_cc_destroy(sln_digest_t *d);
#endif

selene_error_t* sln_digest_openssl_create(selene_t *s, sln_digest_e type, sln_digest_t **p_digest);
void sln_digest_openssl_update(sln_digest_t *digest, const void *data, size_t len);
void sln_digest_openssl_final(sln_digest_t *digest, unsigned char *md);
void sln_digest_openssl_destroy(sln_digest_t *d);

/* TODO: windows */
#ifdef SLN_HAVE_OSX_COMMONCRYPTO
/* Use OSX native methods if available */
#define sln_digest_create sln_digest_osx_cc_create
#define sln_digest_update sln_digest_osx_cc_update
#define sln_digest_final sln_digest_osx_cc_final
#define sln_digest_destroy sln_digest_osx_cc_destroy
#else
/* OpenSSL Fallbacks */
#define sln_digest_create sln_digest_openssl_create
#define sln_digest_update sln_digest_openssl_update
#define sln_digest_final sln_digest_openssl_final
#define sln_digest_destroy sln_digest_openssl_destroy
#endif

#endif
