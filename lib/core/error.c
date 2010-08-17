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

#ifdef LINUX
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "selene_error.h"

selene_error_t*
selene_error_create_impl(selene_status_t err,
                         const char *msg,
                         uint32_t line,
                         const char *file)
{
  selene_error_t *e;

  e = malloc(sizeof(*e));

  e->err = err;
  e->msg = strdup(msg);
  e->line = line;
  e->file = strdup(file);

  return e;
}

selene_error_t *
selene_error_createf_impl(selene_status_t err,
                          uint32_t line,
                          const char *file,
                          const char *fmt,
                          ...)
{
  selene_error_t *e;
  va_list ap;

  e = malloc(sizeof(*e));

  e->err = err;

  va_start(ap, fmt);
  vasprintf((char **) &e->msg, fmt, ap);
  va_end(ap);

  e->line = line;
  e->file = strdup(file);

  return e;
}

void
selene_error_clear(selene_error_t *err)
{
    if (err) {
        free((void *) err->msg);
        free((void *) err->file);
        free(err);
    }
}
