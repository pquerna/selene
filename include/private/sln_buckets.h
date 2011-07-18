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


#ifndef _sln_buckets_h_
#define _sln_buckets_h_

#include "selene.h"
#include "sln_types.h"

/* Create an empty memory bucket, of a specififed size */
selene_error_t*
sln_bucket_create_empty(selene_alloc_t *alloc, sln_bucket_t **b, size_t size);

/* Create a memory buffer, copying the bytes */
selene_error_t*
sln_bucket_create_copy_bytes(selene_alloc_t *alloc, sln_bucket_t **b, const char* bytes, size_t size);

/* Create a memory buffer, taking ownership of the bytes (including calling free()) */
selene_error_t*
sln_bucket_create_with_bytes(selene_alloc_t *alloc, sln_bucket_t **b, char* bytes, size_t size);

/* Create a new bucket, which references a slice from an existing bucket.  This increments
 * the reference count of the parent.  This method is not re-entrant safe across single parent buckets.
 */
selene_error_t*
sln_bucket_create_from_bucket(selene_alloc_t *alloc, sln_bucket_t **out_b,
                              sln_bucket_t *parent, size_t offset, size_t length);

/* Cleanup a memory buffer */
void
sln_bucket_destroy(sln_bucket_t *b);

#define SLN_BUCKET_REMOVE(e) SLN_RING_REMOVE((e), link)

#endif
