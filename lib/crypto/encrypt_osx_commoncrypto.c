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

#ifdef SLN_HAVE_OSX_COMMONCRYPTO

#include "sln_types.h"
#include "sln_hmac.h"
#include <CommonCrypto/CommonCryptor.h>

selene_error_t *sln_cryptor_osx_cc_create(selene_t *s, int encrypt,
                                          sln_cipher_e type, const char *key,
                                          const char *iv,
                                          sln_cryptor_t **p_enc) {
  CCCryptorStatus rv;
  CCCryptorRef cryptor;
  size_t keylen;
  CCAlgorithm alg;
  CCOperation op;

  if (encrypt) {
    op = kCCEncrypt;
  } else {
    op = kCCDecrypt;
  }
  switch (type) {
    case SLN_CIPHER_AES_128_CBC:
      alg = kCCAlgorithmAES128;
      keylen = kCCKeySizeAES128;
      break;
    case SLN_CIPHER_AES_256_CBC:
      /* TODO: it is not clear from the docs why this is named AES-128, but if
       * you
       * pass in a key size that is for AES-256, it works (?????) as if it was
       * in AES-256 mode (!!!!!)
       */
      alg = kCCAlgorithmAES128;
      keylen = kCCKeySizeAES256;
      break;
    case SLN_CIPHER_RC4:
      alg = kCCAlgorithmRC4;
      keylen = SLN_CIPHER_RC4_128_KEY_LENGTH;
      break;
    default:
      return selene_error_createf(SELENE_ENOTIMPL,
                                  "Unsupported cipher type: %d", type);
  }

  rv = CCCryptorCreate(op, alg, 0, key, keylen, iv, &cryptor);

  if (rv != kCCSuccess) {
    return selene_error_createf(
        SELENE_EIO, "CCCryptorCreate failed CCCryptorStatus=%d", rv);
  } else {
    sln_cryptor_t *enc = sln_alloc(s, sizeof(sln_cryptor_t));
    enc->s = s;
    enc->baton = cryptor;
    enc->type = type;
    *p_enc = enc;
  }

  return SELENE_SUCCESS;
}

void sln_cryptor_osx_cc_encrypt(sln_cryptor_t *enc, const void *data,
                                size_t len, char *buf, size_t *blen) {
  /* TODO: output buffer must be exactly the right size, our interface never
   * pads for you */
  CCCryptorRef cryptor = enc->baton;

  CCCryptorUpdate(cryptor, data, len, buf, *blen, blen);
}

void sln_cryptor_osx_cc_destroy(sln_cryptor_t *enc) {
  selene_t *s = enc->s;
  CCCryptorRef cryptor = enc->baton;

  CCCryptorRelease(cryptor);

  sln_free(s, enc);
}

#endif
