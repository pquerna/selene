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

size_t sln_hmac_length(sln_hmac_t *h)
{
  switch (h->type) {
    case SLN_HMAC_MD5:
    {
      return SLN_MD5_DIGEST_LENGTH;
    }
    case SLN_HMAC_SHA1:
    {
      return SLN_SHA1_DIGEST_LENGTH;
    }
  }

  /* unreached */
  return -1;
}
