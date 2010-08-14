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

static int initialized = 0;

static selene_error_t*
sln_initialize(void)
{
  /* TODO: Atomics ? */
  if (initialized++) {
    return SELENE_SUCCESS;
  }

  /* TODO: Backend initilization */
  
  return SELENE_SUCCESS;
}

static void
sln_terminate(void)
{
  initialized--;
  if (initialized) {
    return;
  }

  /* TODO: backend shutdown */

  return;
}

static selene_error_t*
sln_create(selene_t **p_sel, sln_mode_e mode)
{
  selene_t *sel;

  SELENE_ERR(sln_initialize());

  sel = calloc(1, sizeof(selene_t));
  sel->mode = mode;
  sel->state = SLN_STATE_INIT;
  *p_sel = sel;

  return SELENE_SUCCESS;
}

selene_error_t*
selene_client_create(selene_t **p_sel)
{
  return sln_create(p_sel, SLN_MODE_CLIENT);
}

selene_error_t*
selene_server_create(selene_t **p_sel)
{
  return sln_create(p_sel, SLN_MODE_SERVER);
}

void 
selene_destroy(selene_t *sel)
{
  sel->state = SLN_STATE_DEAD;

  free(sel);

  sln_terminate();

}
