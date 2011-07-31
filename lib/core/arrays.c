/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
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

#include "sln_arrays.h"
#include <string.h>

/*****************************************************************
 *
 * The 'array' functions...
 */

static void
make_array_core(sln_array_header_t *res, selene_alloc_t *alloc, int nelts, int elt_size, int clear)
{
    /*
     * Assure sanity if someone asks for
     * array of zero elts.
     */
    if (nelts < 1) {
        nelts = 1;
    }

    if (clear) {
        res->elts = alloc->calloc(alloc->baton, nelts * elt_size);
    }
    else {
        res->elts = alloc->malloc(alloc->baton, nelts * elt_size);
    }

    res->alloc = alloc;
    res->elt_size = elt_size;
    res->nelts = 0;		/* No active elements yet... */
    res->nalloc = nelts;	/* ...but this many allocated */
}

int
sln_is_empty_array(const sln_array_header_t *a)
{
    return ((a == NULL) || (a->nelts == 0));
}

sln_array_header_t*
sln_array_make(selene_alloc_t *alloc, int nelts, int elt_size)
{
    sln_array_header_t *res;

    res = (sln_array_header_t *) alloc->malloc(alloc->baton, sizeof(sln_array_header_t));
    make_array_core(res, alloc, nelts, elt_size, 1);
    return res;
}

void
sln_array_clear(sln_array_header_t *arr)
{
    arr->nelts = 0;
}

void
sln_array_destroy(sln_array_header_t *arr)
{
  selene_alloc_t *alloc = arr->alloc;

  alloc->free(alloc->baton, arr->elts);
  alloc->free(alloc->baton, arr);
}

void*
sln_array_pop(sln_array_header_t *arr)
{
    if (sln_is_empty_array(arr)) {
        return NULL;
    }
   
    return arr->elts + (arr->elt_size * (--arr->nelts));
}

void*
sln_array_push(sln_array_header_t *arr)
{
    if (arr->nelts == arr->nalloc) {
        int new_size = (arr->nalloc <= 0) ? 1 : arr->nalloc * 2;
        char *new_data;

        new_data = arr->alloc->malloc(arr->alloc->baton, arr->elt_size * new_size);

        memcpy(new_data, arr->elts, arr->nalloc * arr->elt_size);
        memset(new_data + arr->nalloc * arr->elt_size, 0,
               arr->elt_size * (new_size - arr->nalloc));
        arr->alloc->free(arr->alloc->baton, arr->elts);
        arr->elts = new_data;
        arr->nalloc = new_size;
    }

    ++arr->nelts;
    return arr->elts + (arr->elt_size * (arr->nelts - 1));
}
