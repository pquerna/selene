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

#include "sln_brigades.h"
#include "sln_types.h"
#include "sln_assert.h"

#include <string.h>

selene_error_t*
sln_brigade_create(selene_alloc_t *alloc, sln_brigade_t **out_bb)
{
  sln_brigade_t* bb = alloc->calloc(alloc->baton, sizeof(sln_brigade_t));

  SLN_RING_INIT(&bb->list, sln_bucket_t, link);

  bb->alloc = alloc;

  *out_bb = bb;

  return SELENE_SUCCESS;
}

void
sln_brigade_destroy(sln_brigade_t *bb)
{
  sln_brigade_clear(bb);

  bb->alloc->free(bb->alloc->baton, bb);
}

void
sln_brigade_clear(sln_brigade_t *bb)
{
  sln_bucket_t *e;

  while (!SLN_BRIGADE_EMPTY(bb)) {
      e = SLN_BRIGADE_FIRST(bb);
      sln_bucket_destroy(e);
  }
}

size_t
sln_brigade_size(sln_brigade_t *bb)
{
  /* TODO: cache current value inside the sln_brigade_t structure */
  size_t total = 0;
  sln_bucket_t *b;

  SLN_RING_FOREACH(b, &(bb)->list, sln_bucket_t, link)
  {
    total += b->size;
  }

  return total;
}

static size_t sln_min(size_t x, size_t y) {
  if (x < y) {
    return x;
  }
  return y;
}

selene_error_t*
sln_brigade_pread_bytes(sln_brigade_t *bb, size_t want_offset, size_t want_length, char *buffer, size_t *got_len)
{
  /* Read into an offset into a buffer, crossing buckets as needed.  This produces
   * a copy of the data -- it is intended to be used for short reads where we are avoiding a malloc,
   * for long reads your should probally use BRIGADE_SLICE, to cut up buckets.
   */
  size_t got = 0;
  size_t offset = 0;
  size_t buffer_offset = 0;
  sln_bucket_t *b;

  SLN_RING_FOREACH(b, &(bb)->list, sln_bucket_t, link)
  {
    if (got == want_length) {
      break;
    }

    if (want_offset <= (offset + b->size)) {
      size_t startpoint = 0;
      if (want_offset > offset) {
        startpoint = want_offset - offset;
      }
      size_t tocopy = sln_min(b->size - startpoint, want_length - got);
      got += tocopy;
      memcpy(buffer+buffer_offset, b->data+startpoint, tocopy);
      buffer_offset += tocopy;
      offset += tocopy;
    }
    else {
      offset += b->size;
      continue;
    }
  }

  *got_len = got;
  return SELENE_SUCCESS;
}

selene_error_t*
sln_brigade_flatten(sln_brigade_t *bb, char *c, size_t *len)
{
  /**
   * This is very similiar to APR's, and based upon apr_brigade_flatten.
   * The fundamental difference is that we consume buckets as they are 
   * stored into the output buffer.
   */

  size_t actual = 0;
  sln_bucket_t *b;
  sln_bucket_t *iter;

  SLN_RING_FOREACH_SAFE(b, iter, &(bb)->list, sln_bucket_t, link)
  {
    size_t data_len = b->size;

    /* If we would overflow. */
    if (data_len + actual > *len) {
      data_len = *len - actual;
    }

    /* XXX: It appears that overflow of the final bucket
     * is DISCARDED without any warning to the caller.
     *
     * No, we only copy the data up to their requested size.  -- jre
     */
    memcpy(c, b->data, data_len);
    c += data_len;
    actual += data_len;

    if (b->size != data_len) {
      sln_bucket_t *tmpe;

      SELENE_ERR(sln_bucket_create_copy_bytes(bb->alloc, &tmpe, (b->data + data_len), b->size - data_len));

      SLN_BRIGADE_INSERT_HEAD(bb, tmpe);
    }

    sln_bucket_destroy(b);

    /* This could probably be actual == *len, but be safe from stray
     * photons. */
    if (actual >= *len) {
        break;
    }
  }

  *len = actual;

  return SELENE_SUCCESS;
}

selene_error_t*
sln_brigade_copy_into(sln_brigade_t *source_bb, size_t want_offset, size_t want_length, sln_brigade_t *into_bb)
{
  selene_error_t* err;
  sln_bucket_t *e;
  size_t rlen = 0;
  size_t tocopy;

  tocopy = sln_min(want_length, sln_brigade_size(source_bb) - want_offset);

  err = sln_bucket_create_empty(into_bb->alloc, &e, tocopy);

  if (err) {
    return err;
  }

  /* TODO: this is maybe not the most efficient method... but fuck it, optimize it later right?*/
  err = sln_brigade_pread_bytes(source_bb, want_offset, tocopy, e->data, &rlen);

  if (err) {
    sln_bucket_destroy(e);
    return err;
  }

  SLN_BRIGADE_INSERT_TAIL(into_bb, e);

  return SELENE_SUCCESS;
}

selene_error_t*
sln_brigade_chomp(sln_brigade_t *bb, size_t len)
{
  size_t actual = 0;
  sln_bucket_t *b;
  sln_bucket_t *iter;

  SLN_RING_FOREACH_SAFE(b, iter, &(bb)->list, sln_bucket_t, link)
  {
    size_t data_len = b->size;

    /* If we would overflow. */
    if (data_len + actual > len) {
      data_len = len - actual;
    }

    actual += data_len;

    if (b->size != data_len) {
      sln_bucket_t *tmpe;

      SELENE_ERR(sln_bucket_create_copy_bytes(bb->alloc, &tmpe, (b->data + data_len), b->size - data_len));

      SLN_BRIGADE_INSERT_HEAD(bb, tmpe);
    }

    sln_bucket_destroy(b);

    /* This could probably be actual == *len, but be safe from stray
     * photons. */
    if (actual >= len) {
        break;
    }
  }

  return SELENE_SUCCESS;
}
