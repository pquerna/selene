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
#include <string.h>

void* sln_conf_alloc(selene_conf_t *conf, size_t len)
{
  return conf->alloc->malloc(conf->alloc->baton, len);
}

void* sln_conf_calloc(selene_conf_t *conf, size_t len)
{
  return conf->alloc->calloc(conf->alloc->baton, len);
}

void sln_conf_free(selene_conf_t *conf, void *ptr)
{
  conf->alloc->free(conf->alloc->baton, ptr);
}

void* sln_alloc(selene_t *s, size_t len)
{
  return s->conf->alloc->malloc(s->conf->alloc->baton, len);
}

void* sln_calloc(selene_t *s, size_t len)
{
  return s->conf->alloc->calloc(s->conf->alloc->baton, len);
}

void sln_free(selene_t *s, void *ptr)
{
  s->conf->alloc->free(s->conf->alloc->baton, ptr);
}

char *sln_conf_strdup(selene_conf_t *conf, const char *in)
{
  /* LAME: why am i doing this */
  char *dest;

  size_t len = strlen(in) + 1;

  dest = sln_conf_alloc(conf, len);
  memcpy(dest, in, len);

  return dest;
}

char *sln_strdup(selene_t *s, const char *in)
{
  return sln_conf_strdup(s->conf, in);
}
