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
#include "sln_brigades.h"

selene_error_t*
sln_iobb_create(selene_alloc_t *alloc, sln_iobb_t *iobb)
{
  SELENE_ERR(sln_brigade_create(alloc, &iobb->in_enc));
  SELENE_ERR(sln_brigade_create(alloc, &iobb->out_enc));
  SELENE_ERR(sln_brigade_create(alloc, &iobb->in_cleartext));
  SELENE_ERR(sln_brigade_create(alloc, &iobb->out_cleartext));
  return SELENE_SUCCESS;
}

void
sln_iobb_destroy(sln_iobb_t *iobb)
{
  sln_brigade_destroy(iobb->in_enc);
  sln_brigade_destroy(iobb->out_enc);
  sln_brigade_destroy(iobb->in_cleartext);
  sln_brigade_destroy(iobb->out_cleartext);
}


SELENE_API(selene_error_t*)
selene_io_in_clear_bytes(selene_t *s,
                         const char* bytes,
                         size_t length)
{
  sln_bucket_t *e = NULL;

  SELENE_ERR(sln_bucket_create_copy_bytes(s->alloc, &e, bytes, length));

  SLN_BRIGADE_INSERT_TAIL(s->bb.in_cleartext, e);

  SELENE_ERR(selene_publish(s, SELENE_EVENT_IO_IN_CLEAR));

  return SELENE_SUCCESS;
}


SELENE_API(selene_error_t*)
selene_io_in_clear_iovec(selene_t *s, const struct iovec *vec, int iovcnt)
{
  int i;
  sln_bucket_t *e = NULL;

  /* TODO: possible to optimize this? */
  for (i = 0; i < iovcnt; i++) {
    SELENE_ERR(sln_bucket_create_copy_bytes(s->alloc, &e, vec[i].iov_base, vec[i].iov_len));
    SLN_BRIGADE_INSERT_TAIL(s->bb.in_enc, e);
  }

  SELENE_ERR(selene_publish(s, SELENE_EVENT_IO_IN_CLEAR));

  return SELENE_SUCCESS;
}

SELENE_API(selene_error_t*)
selene_io_in_enc_bytes(selene_t *s,
                       const char* bytes,
                       size_t length)
{
  sln_bucket_t *e = NULL;

  SELENE_ERR(sln_bucket_create_copy_bytes(s->alloc, &e, bytes, length));

  SLN_BRIGADE_INSERT_TAIL(s->bb.in_enc, e);

  SELENE_ERR(selene_publish(s, SELENE_EVENT_IO_IN_ENC));

  return SELENE_SUCCESS;
}

static selene_error_t*
bb_chomp_to_buffer(selene_t *s,
                   sln_brigade_t *bb,
                   char* buffer,
                   size_t blen,
                   size_t *length,
                   size_t *remaining)
{
  *remaining = 0;
  *length = 0;

  if (!SLN_BRIGADE_EMPTY(bb)) {
    size_t tlen = blen;

    SELENE_ERR(sln_brigade_flatten(bb, buffer, &tlen));

    *remaining = sln_brigade_size(bb);
    *length = tlen;
  }

  return SELENE_SUCCESS;
}

SELENE_API(selene_error_t*)
selene_io_out_clear_bytes(selene_t *s,
                          char* buffer,
                          size_t blen,
                          size_t *length,
                          size_t *remaining)
{
  return bb_chomp_to_buffer(s, s->bb.out_cleartext, buffer, blen, length, remaining);
}


SELENE_API(selene_error_t*)
selene_io_out_enc_bytes(selene_t *s,
                        char* buffer,
                        size_t blen,
                        size_t *length,
                        size_t *remaining)
{
  return bb_chomp_to_buffer(s, s->bb.out_enc, buffer, blen, length, remaining);
}

