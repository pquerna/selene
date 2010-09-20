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

#include "selene.h"
#include "sln_types.h"
#include <string.h>

selene_error_t *
selene_conf_use_reasonable_defaults(selene_t *s)
{
  SELENE_ERR(selene_conf_cipher_suites(s, SELENE_CS_RSA_WITH_RC4_128_SHA | 
                                             SELENE_CS_RSA_WITH_AES_128_CBC_SHA |
                                             SELENE_CS_RSA_WITH_AES_256_CBC_SHA));

  SELENE_ERR(selene_conf_protocols(s, SELENE_PROTOCOL_SSL30 | 
                                         SELENE_PROTOCOL_TLS10 |
                                         SELENE_PROTOCOL_TLS11 |
                                         SELENE_PROTOCOL_TLS12));

  return SELENE_SUCCESS;
}

selene_error_t *
selene_conf_cipher_suites(selene_t *s, int ciphers)
{
  /* TODO: assert on inalid ciphers */
  s->conf.ciphers = ciphers;
  return SELENE_SUCCESS;
}

selene_error_t *
selene_conf_protocols(selene_t *s, int protocols)
{
  /* TODO: assert on inalid protocols */
  s->conf.protocols = protocols;
  return SELENE_SUCCESS;
}

selene_error_t *
selene_conf_name_indication(selene_t *s, const char *hostname)
{
  SLN_ERR_CLIENT_ONLY(s);

  if (s->conf.sni != NULL) {
    free((void*)s->conf.sni);
  }

  if (hostname) {
    s->conf.sni = strdup(hostname);
  }
  else {
    s->conf.sni = NULL;
  }

  return SELENE_SUCCESS;
}
