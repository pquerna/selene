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
#include "sln_prf.h"

#include <string.h>

static selene_error_t*
prf_hash(selene_t *s,
         sln_hmac_e htype,
         const char *secret,
         size_t secretlen,
         const char *seed,
         size_t seedlen,
         char *output,
         size_t outlen)
{
  sln_hmac_t *a_hmac;
  unsigned char a_hmac_buf[SLN_BIG_DIGEST_LENGTH];
  char *a_buf = NULL;
  size_t a_buf_len;
  selene_error_t *err = SELENE_SUCCESS;
  size_t hashlen;

  SELENE_ERR(sln_hmac_create(s, htype, secret, secretlen, &a_hmac));

  hashlen = sln_hmac_length(a_hmac);

  sln_hmac_update(a_hmac, seed, seedlen);

  sln_hmac_final(a_hmac, a_hmac_buf);

  sln_hmac_destroy(a_hmac);

  /* TODO: efficiency */
  a_buf_len = seedlen + hashlen;
  a_buf = sln_alloc(s, a_buf_len);
  memcpy(a_buf, a_hmac_buf, hashlen);
  memcpy(a_buf + hashlen, seed, seedlen);

  while (outlen > 0) {
    sln_hmac_t *hmac;
    size_t adv;
    unsigned char buf[SLN_BIG_DIGEST_LENGTH];

    err = sln_hmac_create(s, htype, secret, secretlen, &hmac);

    if (err) {
      break;
    }

    sln_hmac_update(hmac, a_buf, a_buf_len);

    sln_hmac_final(hmac, buf);

    sln_hmac_destroy(hmac);

    if (hashlen < outlen) {
      adv = hashlen;
    }
    else {
      adv = outlen;
    }

    memcpy(output, buf, adv);

    outlen -= adv;
    output += adv;

    if (outlen != 0) {
      err = sln_hmac_create(s, htype, secret, secretlen, &a_hmac);

      if (err) {
        break;
      }
      sln_hmac_update(a_hmac, a_buf, hashlen);
      sln_hmac_final(a_hmac, a_hmac_buf);
      sln_hmac_destroy(a_hmac);
    }
  }

  if (a_buf) {
    sln_free(s, a_buf);
  }

  return err;
}


selene_error_t*
sln_prf(selene_t *s,
  const char *label,
  size_t labellen,
  const char *secret,
  size_t secretlen,
  const char *seed,
  size_t seedlen,
  char *output,
  size_t outlen)
{
  selene_error_t *err = SELENE_SUCCESS;
  size_t i;
  size_t half_secretlen;
  size_t concatlen = labellen + seedlen;
  char *concat = sln_alloc(s, labellen + seedlen);
  char *tmpout = sln_alloc(s, outlen);

  memcpy(concat, label, labellen);
  memcpy(concat + labellen, seed, seedlen);

  half_secretlen = (secretlen / 2) + (secretlen % 2);

  
  /* We store the MD5 HMAC in the initial output, and need to allocate
   * a temp area for the SHA1 HMAC, to then XOR them together.
   */

  err = prf_hash(s, SLN_HMAC_MD5,
                 secret, half_secretlen,
                 concat, concatlen,
                 output, outlen);

  if (err) {
    goto out;
  }

  err = prf_hash(s, SLN_HMAC_SHA1,
                 secret + (secretlen / 2), half_secretlen,
                 concat, concatlen,
                 tmpout, outlen);
  if (err) {
    goto out;
  }

  for (i = 0; i < outlen; i++) {
    output[i] ^= tmpout[i];
  }

out:
  sln_free(s, tmpout);
  sln_free(s, concat);

  return err;
}
