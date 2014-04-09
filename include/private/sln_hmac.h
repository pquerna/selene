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

#ifndef _sln_hmac_h_
#define _sln_hmac_h_

#ifdef SLN_HAVE_OSX_COMMONCRYPTO
selene_error_t *sln_hmac_osx_cc_create(selene_t *s, sln_hmac_e type,
                                       const char *key, size_t klen,
                                       sln_hmac_t **p_hmac);
void sln_hmac_osx_cc_update(sln_hmac_t *digest, const void *data, size_t len);
void sln_hmac_osx_cc_final(sln_hmac_t *digest, unsigned char *md);
void sln_hmac_osx_cc_destroy(sln_hmac_t *d);
#endif

selene_error_t *sln_hmac_openssl_create(selene_t *s, sln_hmac_e type,
                                        const char *key, size_t klen,
                                        sln_hmac_t **p_hmac);
void sln_hmac_openssl_update(sln_hmac_t *digest, const void *data, size_t len);
void sln_hmac_openssl_final(sln_hmac_t *digest, unsigned char *md);
void sln_hmac_openssl_destroy(sln_hmac_t *d);

/* TODO: windows */
#ifdef SLN_HAVE_OSX_COMMONCRYPTO
/* Use OSX native methods if available */
#define sln_hmac_create sln_hmac_osx_cc_create
#define sln_hmac_update sln_hmac_osx_cc_update
#define sln_hmac_final sln_hmac_osx_cc_final
#define sln_hmac_destroy sln_hmac_osx_cc_destroy
#else
/* OpenSSL Fallbacks */
#define sln_hmac_create sln_hmac_openssl_create
#define sln_hmac_update sln_hmac_openssl_update
#define sln_hmac_final sln_hmac_openssl_final
#define sln_hmac_destroy sln_hmac_openssl_destroy
#endif

size_t sln_hmac_length(sln_hmac_t *d);

#endif
