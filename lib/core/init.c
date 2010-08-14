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


#include "selene.h"
#include "sln_types.h"

selene_error_t*
selene_create(selene_t **p_sel)
{
  selene_t *sel = calloc(1, sizeof(selene_t));
  sel->state =  SLN_STATE_INIT;
  *p_sel = sel;

  return SELENE_SUCCESS;
}

void 
selene_destroy(selene_t *sel)
{
  sel->state = SLN_STATE_DEAD;

  free(sel);
}