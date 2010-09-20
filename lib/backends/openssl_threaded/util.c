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

#include "openssl_threaded.h"

char* 
sln_ot_ciphers_to_openssl(int selene_ciphers)
{
  /* TODO: find a better max for cipher counts */
  const char *argv[32] = {0};
  int i = 0;
  int j = 0;
  size_t size = 0;

  if (selene_ciphers & SELENE_CS_RSA_WITH_RC4_128_SHA) {
    argv[i] = "RC4-SHA:";
    size += strlen(argv[i++]);
  }

  if (selene_ciphers & SELENE_CS_RSA_WITH_AES_128_CBC_SHA) {
    argv[i] = "AES128-SHA:";
    size += strlen(argv[i++]);
  }

  if (selene_ciphers & SELENE_CS_RSA_WITH_AES_256_CBC_SHA) {
    argv[i] = "AES256-SHA:";
    size += strlen(argv[i++]);
  }

  if (i == 0) {
    return NULL;
  }

  char *out = malloc(size + 1);
  size_t off = 0;

  for (j = 0; j < i; j++) {
    size_t l = strlen(argv[j]);
    memcpy(out+off, argv[j], l);
    off += l;
  }

  out[off-1] = '\0';

  return out;
}
