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

#include "sln_brigades.h"
#include "sln_types.h"


selene_error_t*
sln_brigade_create(sln_brigade_t **out_bb)
{
  sln_brigade_t* bb = calloc(1, sizeof(sln_brigade_t));

  SLN_RING_INIT(&bb->list, sln_bucket_t, link);

  *out_bb = bb;

  return SELENE_SUCCESS;
}

selene_error_t*
sln_brigade_destroy(sln_brigade_t *bb)
{
  SELENE_ERR(sln_brigade_clear(bb));

  free(bb);

  return SELENE_SUCCESS;
}

selene_error_t*
sln_brigade_clear(sln_brigade_t *bb)
{
  sln_bucket_t *e;

  while (!SLN_BRIGADE_EMPTY(bb)) {
      e = SLN_BRIGADE_FIRST(bb);
      sln_bucket_destroy(e);
  }

  return SELENE_SUCCESS;
}
