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

#ifndef _sln_tests_h_
#define _sln_tests_h_

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include "sln_types.h"
#include "sln_assert.h"
#include "cmockery.h"

/* TODO: could be built differently if we wanted a testall program */
#define SLN_TESTS_START() \
  int main(int argc, char* argv[]) { \
    const UnitTest tests[] = {

#define SLN_TESTS_ENTRY(entry) \
        unit_test(entry), \

#define SLN_TESTS_END() \
    }; \
    return run_tests(tests); \
  }

#undef SLN_ASSERT
#define SLN_ASSERT(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);

#undef SLN_ERR
#define SLN_ERR(expression) \
  do { \
    selene_error_t *selene__xx__err; \
    SLN_ASSERT((selene__xx__err = (expression)) == SELENE_SUCCESS); \
  } while (0)


#endif

