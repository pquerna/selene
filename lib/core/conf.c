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

selene_error_t*
selene_conf_create(selene_conf_t **p_conf)
{
  selene_conf_t *conf;

  conf = calloc(1, sizeof(selene_conf_t));

  *p_conf = conf;

  return SELENE_SUCCESS;
}



void
selene_conf_destroy(selene_conf_t *conf)
{
  /* TODO: is it worth ref counting this object? Maybe in debug mode only? */
  if (conf->sni != NULL) {
    free((void*)conf->sni);
    conf->sni = NULL;
  }

  free(conf);
}

selene_error_t *
selene_conf_use_reasonable_defaults(selene_conf_t *conf)
{
  SELENE_ERR(selene_conf_cipher_suites(conf, SELENE_CS_RSA_WITH_RC4_128_SHA | 
                                             SELENE_CS_RSA_WITH_AES_128_CBC_SHA |
                                             SELENE_CS_RSA_WITH_AES_256_CBC_SHA));

  SELENE_ERR(selene_conf_protocols(conf, SELENE_PROTOCOL_SSL30 | 
                                         SELENE_PROTOCOL_TLS10 |
                                         SELENE_PROTOCOL_TLS11 |
                                         SELENE_PROTOCOL_TLS12));

  return SELENE_SUCCESS;
}

selene_error_t *
selene_conf_cipher_suites(selene_conf_t *conf, int ciphers)
{
  /* TODO: assert on inalid ciphers */
  conf->ciphers = ciphers;
  return SELENE_SUCCESS;
}

selene_error_t *
selene_conf_protocols(selene_conf_t *conf, int protocols)
{
  /* TODO: assert on inalid protocols */
  conf->protocols = protocols;
  return SELENE_SUCCESS;
}

selene_error_t *
selene_conf_name_indication(selene_conf_t *conf, const char *hostname)
{
  /* TODO: this might not make sense as a selene_conf (?) */

  if (conf->sni != NULL) {
    free((void*)conf->sni);
  }

  if (hostname) {
    conf->sni = strdup(hostname);
  }
  else {
    conf->sni = NULL;
  }

  return SELENE_SUCCESS;
}
