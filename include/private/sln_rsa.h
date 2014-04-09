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

#ifndef _sln_rsa_h_
#define _sln_rsa_h_

#ifdef SLN_HAVE_OSX_COMMONCRYPTO
selene_error_t *sln_rsa_osx_cc_public_encrypt(selene_t *s, sln_pubkey_t *key,
                                              const char *input,
                                              size_t inputlen, char *output);
size_t sln_rsa_osx_cc_size(sln_pubkey_t *key);
#endif

selene_error_t *sln_rsa_openssl_public_encrypt(selene_t *s, sln_pubkey_t *key,
                                               const char *input,
                                               size_t inputlen, char *output);
size_t sln_rsa_openssl_size(sln_pubkey_t *key);

#if defined(SLN_HAVE_OSX_COMMONCRYPTO) && defined(__never__)
#define sln_rsa_public_encrypt sln_rsa_osx_cc_public_encrypt
#define sln_rsa_size sln_rsa_osx_cc_size
#else
#define sln_rsa_public_encrypt sln_rsa_openssl_public_encrypt
#define sln_rsa_size sln_rsa_openssl_size
#endif

#endif
