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

#include "common.h"
#include <openssl/rand.h>


void
sln_parser_tls_set_current_version(selene_t *s, uint8_t *major, uint8_t *minor)
{
  /* TODO: client neg version */
  *major = 3;
  *minor = 1;
}

void
sln_parser_tls_max_supported_version(selene_t *s, uint8_t *major, uint8_t *minor)
{
  /* TODO: TLS 1.2 */
  *major = 3;
  *minor = 1;
}

void
sln_parser_rand_bytes_secure(char *bytes, size_t len)
{
  RAND_bytes((unsigned char *)bytes, len);
}
