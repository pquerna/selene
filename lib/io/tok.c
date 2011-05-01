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
#include "sln_tok.h"
#include <string.h>

selene_error_t*
sln_tok_parser(sln_brigade_t *bb, sln_tok_cb cb, void *baton)
{
  selene_error_t* err = SELENE_SUCCESS;
  sln_tok_value_t tvalue;
  size_t rlen;
  size_t offset = 0;

  memset(&tvalue, 0, sizeof(tvalue));

  tvalue.current = TOK_INIT;

  err = cb(&tvalue, baton);

  if (err) {
    return err;
  }

  tvalue.current = tvalue.next;
  switch (tvalue.next) {
    case TOK__UNUSED:
    case TOK__MAX:
    case TOK_INIT:
    case TOK_DONE:
      break;

    case TOK_SINGLE_BYTE:
      err = sln_brigade_pread_bytes(bb, offset, 1, &tvalue.v.byte, &rlen);
      if (err) {
        return err;
      }
      break;
    case TOK_SLICE_BRIGADE:
      break;
  }

  tvalue.current = TOK__UNUSED;

  return err;
}
