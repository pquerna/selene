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
#include "sln_digest.h"

selene_error_t*
sln_digest_openssl_create(selene_t *s, sln_digest_e type, sln_digest_t **p_digest)
{
  sln_digest_t *d = sln_alloc(s, sizeof(sln_digest_t));
  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  const EVP_MD *mt = NULL;

  d->s = s;
  d->type = type;
  d->baton = mdctx;

  switch (d->type) {
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

  EVP_MD_CTX_init(mdctx);
  EVP_DigestInit_ex(mdctx, mt, NULL);

  *p_digest = d;

  return SELENE_SUCCESS;
}

void
sln_digest_openssl_update(sln_digest_t *d, const void *data, size_t len)
{
  EVP_MD_CTX *mdctx = d->baton;
  EVP_DigestUpdate(mdctx, data, len);
}

void
sln_digest_openssl_final(sln_digest_t *d, unsigned char *md)
{
  EVP_MD_CTX *mdctx = d->baton;
  EVP_DigestFinal_ex(mdctx, md, NULL);
}

void
sln_digest_openssl_destroy(sln_digest_t *d)
{
  selene_t *s = d->s;
  EVP_MD_CTX *mdctx = d->baton;

  EVP_MD_CTX_destroy(mdctx);

  sln_free(s, d);
}

