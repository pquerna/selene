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

#ifndef _sln_encrypt_h_
#define _sln_encrypt_h_


size_t sln_cryptor_blocksize(sln_cryptor_t *enc);

#ifdef SLN_HAVE_OSX_COMMONCRYPTO
selene_error_t* sln_cryptor_osx_cc_create(selene_t *s, sln_cipher_e type, const char* key, const char* iv, sln_cryptor_t **p_enc);
void sln_cryptor_osx_cc_encrypt(sln_cryptor_t *enc, const void *data, size_t len, char *buf, size_t *blen);
void sln_cryptor_osx_cc_destroy(sln_cryptor_t *enc);
#endif

selene_error_t* sln_cryptor_openssl_create(selene_t *s, sln_cipher_e type, const char* key, const char* iv, sln_cryptor_t **p_enc);
void sln_cryptor_openssl_encrypt(sln_cryptor_t *enc, const void *data, size_t len, char *buf, size_t *blen);
void sln_cryptor_openssl_destroy(sln_cryptor_t *enc);

/* TODO: windows */
#if defined(SLN_HAVE_OSX_COMMONCRYPTO) && 0
/* Use OSX native methods if available */
#define sln_cryptor_create sln_cryptor_osx_cc_create
#define sln_cryptor_encrypt sln_cryptor_osx_cc_encrypt
#define sln_cryptor_destroy sln_cryptor_osx_cc_destroy
#else
/* OpenSSL Fallbacks */
#define sln_cryptor_create sln_cryptor_openssl_create
#define sln_cryptor_encrypt sln_cryptor_openssl_encrypt
#define sln_cryptor_destroy sln_cryptor_openssl_destroy
#endif

#endif
