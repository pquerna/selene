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
#include "sln_hmac.h"
#include <openssl/aes.h>
#include <openssl/obj_mac.h>

selene_error_t *sln_cryptor_openssl_create(selene_t *s, int encypt,
                                           sln_cipher_e type, const char *key,
                                           const char *iv,
                                           sln_cryptor_t **p_enc) {
  sln_cryptor_t *enc;
  const EVP_CIPHER *cipherType = NULL;
  EVP_CIPHER_CTX *ctx;

  switch (type) {
    case SLN_CIPHER_AES_128_CBC:
      cipherType = EVP_get_cipherbyname(SN_aes_128_cbc);
      break;
    case SLN_CIPHER_AES_256_CBC:
      cipherType = EVP_get_cipherbyname(SN_aes_256_cbc);
      break;
    case SLN_CIPHER_RC4:
      cipherType = EVP_get_cipherbyname(SN_rc4);
      break;
    default:
      return selene_error_createf(SELENE_ENOTIMPL,
                                  "Unsupported cipher type: %d", type);
  }

  if (cipherType == NULL) {
    return selene_error_createf(
        SELENE_ENOTIMPL,
        "Unsupported cipher type (even though it should be): %d", type);
  }

  ctx = sln_alloc(s, sizeof(EVP_CIPHER_CTX));

  /* TODO: engine support (?) */
  /* TODO: encrypt/decrypt mode */
  EVP_CipherInit_ex(ctx, cipherType, NULL, (const unsigned char *)key,
                    (const unsigned char *)iv, encypt);

  enc = sln_alloc(s, sizeof(sln_cryptor_t));
  enc->s = s;
  enc->baton = ctx;
  enc->type = type;
  *p_enc = enc;

  return SELENE_SUCCESS;
}

void sln_cryptor_openssl_encrypt(sln_cryptor_t *enc, const void *data,
                                 size_t len, char *buf, size_t *blen) {
  EVP_CIPHER_CTX *ctx = enc->baton;
  int outl = *blen;

  EVP_CipherUpdate(ctx, (unsigned char *)buf, &outl, data, len);

  *blen = outl;
}

void sln_cryptor_openssl_destroy(sln_cryptor_t *enc) {
  selene_t *s = enc->s;
  EVP_CIPHER_CTX *ctx = enc->baton;

  EVP_CIPHER_CTX_cleanup(ctx);

  sln_free(s, enc);
}
