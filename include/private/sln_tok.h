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

typedef enum sln_tok_value_e {
  /* TODO: rethink types */
  TOK__UNUSED,
  TOK_INIT,
  TOK_COPY_BYTES,
  TOK_SLICE_BRIGADE,
  TOK_DONE,
  TOK__MAX
} sln_tok_value_e;

#define SLN_TOK_VALUE_MAX_BYTE_COPY_LEN 16

typedef struct sln_tok_value_t {
  sln_tok_value_e current;
  sln_tok_value_e next;
  size_t wantlen;
  union {
    char bytes[SLN_TOK_VALUE_MAX_BYTE_COPY_LEN];
    sln_brigade_t *bb;
  } v;
} sln_tok_value_t;

typedef selene_error_t* (sln_tok_cb)(sln_tok_value_t *v, void *baton);

selene_error_t* sln_tok_parser(sln_brigade_t *bb, sln_tok_cb cb, void *baton);

#endif
