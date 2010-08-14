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

#ifndef _sln_assert_h_
#define _sln_assert_h_

#ifdef DEBUG
/* TODO: move to scons */
#define WANT_SLN_ASSERTS
#endif

#ifdef WANT_SLN_ASSERTS

  #include <assert.h>

  #define SLN_ASSERT(exp) assert(exp)

  #define SLN_ASSERT_RANGE(start, end, target) assert(target > start); assert(target < end);

  #define SLN_ASSERT_ENUM(type, target) SLN_ASSERT_RANGE(type ## __UNUSED0, type ## __MAX, target)

  #define SLN_ASSERT_CONTEXT(ctxt) do { \
    SLN_ASSERT(ctxt != NULL); \
    SLN_ASSERT_ENUM(SLN_MODE, ctxt->mode); \
    SLN_ASSERT_ENUM(SLN_STATE, ctxt->state); \
  } while (0);

#else /* !WANT_SLN_ASSERTS */

  #define SLN_ASSERT(exp)

  #define SLN_ASSERT_RANGE(start, end, target)

  #define SLN_ASSERT_ENUM(type, target)

  #define SLN_ASSERT_CONTEXT(ctxt)

#endif

#endif
