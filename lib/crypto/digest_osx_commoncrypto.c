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
#include "sln_digest.h"
#include <CommonCrypto/CommonDigest.h>

selene_error_t *sln_digest_osx_cc_create(selene_t *s, sln_digest_e type,
                                         sln_digest_t **p_digest) {
  sln_digest_t *d = sln_alloc(s, sizeof(sln_digest_t));
  d->s = s;
  d->type = type;

  switch (type) {
    case SLN_DIGEST_MD5: {
      CC_MD5_CTX *c = sln_alloc(s, sizeof(CC_MD5_CTX));
      CC_MD5_Init(c);
      d->baton = c;
      break;
    }
    case SLN_DIGEST_SHA1: {
      CC_SHA1_CTX *c = sln_alloc(s, sizeof(CC_SHA1_CTX));
      CC_SHA1_Init(c);
      d->baton = c;
      break;
    }
  }

  *p_digest = d;
  return SELENE_SUCCESS;
}

void sln_digest_osx_cc_update(sln_digest_t *d, const void *data, size_t len) {
  switch (d->type) {
    case SLN_DIGEST_MD5: {
      CC_MD5_Update((CC_MD5_CTX *)d->baton, data, len);
      break;
    }
    case SLN_DIGEST_SHA1: {
      CC_SHA1_Update((CC_SHA1_CTX *)d->baton, data, len);
      break;
    }
  }
}

void sln_digest_osx_cc_final(sln_digest_t *d, unsigned char *md) {
  switch (d->type) {
    case SLN_DIGEST_MD5: {
      CC_MD5_Final(md, (CC_MD5_CTX *)d->baton);
      break;
    }
    case SLN_DIGEST_SHA1: {
      CC_SHA1_Final(md, (CC_SHA1_CTX *)d->baton);
      break;
    }
  }
}

void sln_digest_osx_cc_destroy(sln_digest_t *d) {
  selene_t *s = d->s;
  sln_free(s, d->baton);
  sln_free(s, d);
}

#endif
