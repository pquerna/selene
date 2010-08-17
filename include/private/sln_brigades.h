/*
 * Licensed to Paul Querna under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * Paul Querna licenses this file to You under the Apache License, Version 2.0
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

#ifndef _sln_brigades_h_
#define _sln_brigades_h_

#include "selene.h"
#include "sln_types.h"
#include "sln_buckets.h"

selene_error_t*
sln_brigade_create(sln_brigade_t **bb);

/* Destroys the brigade, and all member buckets */
void
sln_brigade_destroy(sln_brigade_t *bb);

/* Cleans out all member buckets, but leaves the brigade intact */
void
sln_brigade_clear(sln_brigade_t *bb);

/* Length of the entire brigade */
size_t
sln_brigade_size(sln_brigade_t *bb);

/**
 * Flatten from the front of the brigade, into a buffer.
 * Buckets up to this point are consumed.
 */
selene_error_t*
sln_brigade_flatten(sln_brigade_t *bb, char *c, size_t *len);

#define SLN_BRIGADE_SENTINEL(b) SLN_RING_SENTINEL(&(b)->list, sln_bucket_t, link)
#define SLN_BRIGADE_EMPTY(b) SLN_RING_EMPTY(&(b)->list, sln_bucket_t, link)
#define SLN_BRIGADE_FIRST(b) SLN_RING_FIRST(&(b)->list)
#define SLN_BRIGADE_LAST(b) SLN_RING_LAST(&(b)->list)

#define SLN_BRIGADE_INSERT_TAIL(b, e) \
  do { \
    sln_bucket_t *sln__b = (e); \
    SLN_RING_INSERT_TAIL(&(b)->list, sln__b, sln_bucket_t, link); \
    SLN_BRIGADE_CHECK_CONSISTENCY((b)); \
  } while (0)

#define SLN_BRIGADE_INSERT_HEAD(b, e) \
  do { \
    sln_bucket_t *sln__b = (e); \
    SLN_RING_INSERT_HEAD(&(b)->list, sln__b, sln_bucket_t, link); \
    SLN_BRIGADE_CHECK_CONSISTENCY((b)); \
  } while (0)

#ifdef SLN_BRIGADE_DEBUG
#define SLN_BRIGADE_CHECK_CONSISTENCY(b) \
  do { \
    SLN_RING_CHECK_CONSISTENCY(&(b)->list, sln_bucket_t, link); \
  } while (0)
#else
#define SLN_BRIGADE_CHECK_CONSISTENCY(b)
#endif

#endif
