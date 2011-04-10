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

#include "native.h"

/* TODO: move to better place */
#define TLS_CLIENT_HELLO 1

selene_error_t*
sln_native_msg_handshake_client_hello_to_bucket(sln_native_msg_client_hello_t *ch, sln_bucket_t **p_b)
{
  sln_bucket_t *b = NULL;
  size_t len = 24 + 1 + 60;

  /* TODO: handle all TLS extensions , and uh, everything else */
  sln_bucket_create_empty(&b, 4 + len);

  b->data[0] = TLS_CLIENT_HELLO;
  b->data[1] = len >> 16;
  b->data[2] = len >> 8;
  b->data[3] = len;

  *p_b = b;

  return SELENE_SUCCESS;
}

