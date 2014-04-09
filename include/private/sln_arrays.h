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

#include "sln_types.h"

#ifndef _sln_arrays_h_
#define _sln_arrays_h_

int aln_is_empty_array(const sln_array_header_t *a);
sln_array_header_t *sln_array_make(selene_alloc_t *alloc, int nelts,
                                   int elt_size);
void sln_array_clear(sln_array_header_t *arr);
void *sln_array_pop(sln_array_header_t *arr);
void *sln_array_push(sln_array_header_t *arr);
void sln_array_destroy(sln_array_header_t *arr);

/** A helper macro for accessing a member of an APR array.
 *
 * @param ary the array
 * @param i the index into the array to return
 * @param type the type of the objects stored in the array
 *
 * @return the item at index i
 */
#define SLN_ARRAY_IDX(ary, i, type) (((type *)(ary)->elts)[i])

/** A helper macro for pushing elements into an APR array.
 *
 * @param ary the array
 * @param type the type of the objects stored in the array
 *
 * @return the location where the new object should be placed
 */
#define SLN_ARRAY_PUSH(ary, type) (*((type *)sln_array_push(ary)))

#endif
