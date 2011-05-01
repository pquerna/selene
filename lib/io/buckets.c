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
#include <string.h>

static void create_sized(sln_bucket_t **out_b, size_t size)
{
  sln_bucket_t *b = calloc(1, sizeof(sln_bucket_t));

  b->memory_is_mine = 1;
  b->size = size;

  SLN_RING_ELEM_INIT(b, link);

  *out_b = b;
}

selene_error_t*
sln_bucket_create_empty(sln_bucket_t **out_b, size_t size)
{
  sln_bucket_t *b = NULL;

  create_sized(&b, size);

  /* TODO: pool allocator */
  b->data = malloc(size);

  *out_b = b;

  return SELENE_SUCCESS;
}

selene_error_t*
sln_bucket_create_copy_bytes(sln_bucket_t **out_b, const char* bytes, size_t size)
{
  sln_bucket_t *b = NULL;

  SELENE_ERR(sln_bucket_create_empty(&b, size));

  memcpy(b->data, bytes, size);

  *out_b = b;

  return SELENE_SUCCESS;
}

selene_error_t*
sln_bucket_create_with_bytes(sln_bucket_t **out_b, char* bytes, size_t size)
{
  sln_bucket_t *b = NULL;

  create_sized(&b, size);

  b->memory_is_mine = 0;

  b->data = bytes;

  return SELENE_SUCCESS;
}

selene_error_t*
sln_bucket_destroy(sln_bucket_t *b)
{
  SLN_BUCKET_REMOVE(b);

  if (b->memory_is_mine == 1) {
    free(b->data);
  }

  free(b);

  return SELENE_SUCCESS;
}
