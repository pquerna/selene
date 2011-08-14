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

#include "sln_types.h"
#include "sln_rsa.h"
#include "sln_assert.h"
#include <openssl/rsa.h>
#include <openssl/err.h>

selene_error_t*
sln_rsa_openssl_public_encrypt(selene_t *s, sln_pubkey_t *key,
                               const char *input, size_t inputlen, char *output)
{
  int err;
  RSA *rsa = key->key->pkey.rsa;

  SLN_ASSERT(key->key->type == EVP_PKEY_RSA);

  err = RSA_public_encrypt(inputlen, (const unsigned char *)input,
                           (unsigned char *)output,
                           rsa, RSA_PKCS1_PADDING);

  if (err) {
    char buf[121];
    unsigned long e = ERR_get_error();
    return selene_error_createf(SELENE_EINVAL,
                                "RSA_public_encrypt error: %s",
                                ERR_error_string(e, buf));
  }

  return SELENE_SUCCESS;
}
