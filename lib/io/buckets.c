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
#include "sln_buckets.h"
#include "sln_types.h"
#include "sln_assert.h"
#include <string.h>

static void create_sized(selene_alloc_t *alloc, sln_bucket_t *parent,
                         size_t size, sln_bucket_t **out_b) {
  sln_bucket_t *b = alloc->calloc(alloc->baton, sizeof(sln_bucket_t));

  b->alloc = alloc;
  b->parent = parent;
  if (parent != NULL) {
    sln_bucket_t *e = parent;
    while (e != NULL) {
      e->refcount++;
      e = e->parent;
    }
    /* TODO: perhaps have a CAS version for multi-threaded operation, but,
     * no.... no. */
    b->memory_is_mine = 0;
  } else {
    b->memory_is_mine = 1;
  }
  b->refcount = 1;
  b->size = size;

  SLN_RING_ELEM_INIT(b, link);

  *out_b = b;
}

selene_error_t *sln_bucket_create_empty(selene_alloc_t *alloc,
                                        sln_bucket_t **out_b, size_t size) {
  sln_bucket_t *b = NULL;

  create_sized(alloc, NULL, size, &b);

  /* TODO: pool allocator */
  b->data = malloc(size);

  *out_b = b;

  return SELENE_SUCCESS;
}

selene_error_t *sln_bucket_create_from_bucket(selene_alloc_t *alloc,
                                              sln_bucket_t **out_b,
                                              sln_bucket_t *parent,
                                              size_t offset, size_t length) {
  sln_bucket_t *b = NULL;

  SLN_ASSERT(parent->size >= offset + length);

  create_sized(alloc, parent, length, &b);

  b->data = parent->data + offset;

  *out_b = b;

  return SELENE_SUCCESS;
}

selene_error_t *sln_bucket_create_copy_bytes(selene_alloc_t *alloc,
                                             sln_bucket_t **out_b,
                                             const char *bytes, size_t size) {
  sln_bucket_t *b = NULL;

  SELENE_ERR(sln_bucket_create_empty(alloc, &b, size));

  memcpy(b->data, bytes, size);

  *out_b = b;

  return SELENE_SUCCESS;
}

selene_error_t *sln_bucket_create_with_bytes(selene_alloc_t *alloc,
                                             sln_bucket_t **out_b, char *bytes,
                                             size_t size) {
  sln_bucket_t *b = NULL;

  create_sized(alloc, NULL, size, &b);

  b->memory_is_mine = 0;

  b->data = bytes;

  *out_b = b;

  return SELENE_SUCCESS;
}

void bucket_try_destroy(sln_bucket_t *b) {
  sln_bucket_t *parent = b->parent;
  b->refcount--;

  /* fprintf(stderr, "bucket_try_destroy: b: %p ref: %d  parent: %p\n",
   * (void*)b, b->refcount, (void*)parent); */
  if (b->refcount <= 0) {
    if (b->memory_is_mine == 1 && b->data != NULL) {
      b->alloc->free(b->alloc->baton, b->data);
    }

    b->data = NULL;

    b->alloc->free(b->alloc->baton, b);
  }

  if (parent) {
    bucket_try_destroy(parent);
  }
}

void sln_bucket_destroy(sln_bucket_t *b) {
  SLN_BUCKET_REMOVE(b);

  bucket_try_destroy(b);
}
