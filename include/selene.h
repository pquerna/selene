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

#ifndef _selene_h_
#define _selene_h_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdlib.h>
#include "selene_visibility.h"
#include "selene_version.h"
#include "selene_error.h"

/** Opaque context of an SSL/TLS Session */
typedef struct selene_t selene_t;

/**
 * Creates a Client SSL/TLS Context.
 */
SELENE_API(selene_error_t*) selene_client_create(selene_t **ctxt);

/**
 * Creates a Server SSL/TLS Context.
 */
SELENE_API(selene_error_t*) selene_server_create(selene_t **ctxt);

/**
 * Destroys a SSL/TLS Context of any type.
 */
SELENE_API(void) selene_destroy(selene_t *ctxt);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _selene_h_ */