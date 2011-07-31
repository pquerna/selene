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
#include <openssl/hmac.h>

selene_error_t*
sln_hmac_openssl_create(selene_t *s, sln_hmac_e type, const char* key, size_t klen, sln_hmac_t **p_hmac)
{
  sln_hmac_t *h = sln_alloc(s, sizeof(sln_hmac_t));
  HMAC_CTX *hctx = sln_alloc(s, sizeof(HMAC_CTX));
  const EVP_MD *mt = NULL;

  h->s = s;
  h->type = type;
  h->baton = hctx;

  switch (h->type) {
    case SLN_DIGEST_MD5:
    {
      mt = EVP_md5();
      break;
    }
    case SLN_DIGEST_SHA1:
    {
      mt = EVP_sha1();
      break;
    }
  }

  HMAC_CTX_init(hctx);
  HMAC_Init_ex(hctx, key, klen, mt, NULL);

  *p_hmac = h;

  return SELENE_SUCCESS;
}

void
sln_hmac_openssl_update(sln_hmac_t *h, const void *data, size_t len)
{
  HMAC_CTX *hctx = h->baton;
  HMAC_Update(hctx, data, len);
}

void
sln_hmac_openssl_final(sln_hmac_t *h, unsigned char *md)
{
  HMAC_CTX *hctx = h->baton;
  HMAC_Final(hctx, md, NULL);
}

void
sln_hmac_openssl_destroy(sln_hmac_t *h)
{
  selene_t *s = h->s;
  HMAC_CTX *hctx = h->baton;

  HMAC_CTX_cleanup(hctx);

  sln_free(s, hctx);
  sln_free(s, h);
}

