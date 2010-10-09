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

#include "sln_backends.h"

selene_error_t*
sln_backend_initialize()
{
#if defined(WANT_OPENSSL_THREADED)
  SELENE_ERR(sln_ot_initilize());
#endif
#if defined(WANT_NATIVE)
  SELENE_ERR(sln_native_initilize());
#endif
  return SELENE_SUCCESS;
}

void
sln_backend_terminate()
{
#if defined(WANT_OPENSSL_THREADED)
  sln_ot_terminate();
#endif
#if defined(WANT_NATIVE)
  sln_native_terminate();
#endif
}

selene_error_t*
sln_backend_create(selene_t *s, sln_backend_e be)
{
  switch (be) {
#if defined(WANT_OPENSSL_THREADED)
    case SLN_BACKEND_OPENSSL_THREADED:
      s->backend.name = "openssl_threaded";
      s->backend.create = sln_ot_create;
      s->backend.start = sln_ot_start;
      s->backend.destroy = sln_ot_destroy;
      return SELENE_SUCCESS;
#endif
#if defined(WANT_NATIVE)
    case SLN_BACKEND_NATIVE:
      s->backend.name = "native";
      s->backend.create = sln_native_create;
      s->backend.start = sln_native_start;
      s->backend.destroy = sln_native_destroy;
      return SELENE_SUCCESS;
#endif
    default:
      break;
  }
  return selene_error_create(SELENE_EINVAL, "no backend available");
}
