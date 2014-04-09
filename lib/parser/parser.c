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

selene_error_t* sln_backend_initialize() {
  SELENE_ERR(sln_parser_initilize());
  return SELENE_SUCCESS;
}

void sln_backend_terminate() { sln_parser_terminate(); }

selene_error_t* sln_backend_create(selene_t* s, sln_backend_e be) {
  s->backend.name = "native parser";
  s->backend.create = sln_parser_create;
  s->backend.start = sln_parser_start;
  s->backend.destroy = sln_parser_destroy;

  return SELENE_SUCCESS;
}
