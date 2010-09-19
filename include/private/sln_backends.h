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

#ifndef _sln_backends_h_
#define _sln_backends_h_

#include "selene.h"
#include "sln_types.h"
#include "sln_buckets.h"

selene_error_t*
sln_backend_create(selene_t *s);

selene_error_t* 
sln_backend_initialize(void);

void
sln_backend_terminate(void);

#if defined(WANT_OPENSSL_THREADED)

selene_error_t*
sln_openssl_threaded_initilize();

void
sln_openssl_threaded_terminate();

selene_error_t*
sln_openssl_threaded_create(selene_t *s);

selene_error_t*
sln_openssl_threaded_start(selene_t *s);

selene_error_t*
sln_openssl_threaded_destroy(selene_t *s);
#endif
  
#endif

