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

#ifndef _sln_tok_h_
#define _sln_tok_h_

#include "sln_brigades.h"

typedef struct sln_tok_value_t {
  size_t want;
  size_t have;
  char *p;
} sln_tok_value_t;

typedef selene_error_t* (sln_tok_cb)(sln_tok_value_t *v, void *baton);

selene_error_t* sln_tok_parser(sln_brigade_t *bb, sln_tok_cb cb, void *baton);

#endif
