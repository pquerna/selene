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
#include <CommonCrypto/CommonHMAC.h>

selene_error_t *sln_hmac_osx_cc_create(selene_t *s, sln_hmac_e type,
                                       const char *key, size_t klen,
                                       sln_hmac_t **p_hmac) {
  sln_hmac_t *h = sln_alloc(s, sizeof(sln_hmac_t));
  CCHmacAlgorithm alg;
  CCHmacContext *c;
  h->s = s;
  h->type = type;

  switch (type) {
    case SLN_HMAC_MD5: {
      alg = kCCHmacAlgMD5;
      break;
    }
    case SLN_HMAC_SHA1: {
      alg = kCCHmacAlgSHA1;
      break;
    }
  }

  c = sln_alloc(s, sizeof(CCHmacContext));

  CCHmacInit(c, alg, key, klen);
  h->baton = c;

  *p_hmac = h;
  return SELENE_SUCCESS;
}

void sln_hmac_osx_cc_update(sln_hmac_t *h, const void *data, size_t len) {
  CCHmacUpdate((CCHmacContext *)h->baton, data, len);
}

void sln_hmac_osx_cc_final(sln_hmac_t *h, unsigned char *md) {
  CCHmacFinal((CCHmacContext *)h->baton, md);
}

void sln_hmac_osx_cc_destroy(sln_hmac_t *h) {
  selene_t *s = h->s;
  sln_free(s, h->baton);
  sln_free(s, h);
}

#endif
