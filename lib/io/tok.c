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

#include <string.h>

#include "selene.h"
#include "sln_types.h"
#include "sln_tok.h"
#include "sln_assert.h"

selene_error_t*
sln_tok_parser(sln_brigade_t *bb, sln_tok_cb cb, void *baton)
{
  int keepgoing = 1;
  selene_error_t* err = SELENE_SUCCESS;
  sln_tok_value_t tvalue;
  size_t rlen;
  size_t offset = 0;
  sln_brigade_t *tmpbb = NULL;

  memset(&tvalue, 0, sizeof(tvalue));

  tvalue.next = TOK_INIT;

  while (keepgoing == 1) {
    tvalue.current = tvalue.next;

    err = cb(&tvalue, baton);

    if (err) {
      keepgoing = 0;
      break;
    }

    switch (tvalue.next) {
      case TOK__UNUSED:
      case TOK__MAX:
      case TOK_INIT:
      case TOK_DONE:
        keepgoing = 0;
        break;

      case TOK_COPY_BYTES:
        SLN_ASSERT(tvalue.wantlen < SLN_TOK_VALUE_MAX_BYTE_COPY_LEN);

        err = sln_brigade_pread_bytes(bb, offset, tvalue.wantlen, &tvalue.v.bytes[0], &rlen);
        if (err) {
          keepgoing = 0;
          break;
        }
        if (rlen != tvalue.wantlen) {
          keepgoing = 0;
        }
        break;

      case TOK_SLICE_BRIGADE:

        if (tvalue.wantlen > sln_brigade_size(bb)) {
          keepgoing = 0;
          break;
        }

        if (tmpbb == NULL) {
          err = sln_brigade_create(&tmpbb);
          if (err) {
            keepgoing = 0;
            break;
          }
        }
        else {
          sln_brigade_clear(tmpbb);
        }

        tvalue.v.bb = tmpbb;
        /* TODO: optimization, this isn't required */
        err = sln_brigade_copy_into(bb, offset, tvalue.wantlen, tmpbb);
        if (err) {
          keepgoing = 0;
          break;
        }
        break;
    }
    offset += tvalue.wantlen;
    tvalue.current = TOK__UNUSED;
  }

  if (tmpbb != NULL) {
    sln_brigade_destroy(tmpbb);
  }

  return err;
}
