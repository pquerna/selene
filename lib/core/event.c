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
#include "sln_assert.h"

selene_error_t*
sln_subscribe(selene_t *ctxt, selene_event_e event,
              int priority,
              selene_event_cb cb, void *baton)
{
  return SELENE_SUCCESS;
}

selene_error_t*
selene_subscribe(selene_t *ctxt, selene_event_e event,
                 selene_event_cb cb, void *baton)
{
  SLN_ASSERT_CONTEXT(ctxt);
  SLN_ASSERT_ENUM(SELENE_EVENT, event);
  return sln_subscribe(ctxt, event, 0, cb, baton);
}
