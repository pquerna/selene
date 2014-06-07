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

#ifndef _sln_tests_h_
#define _sln_tests_h_

#ifndef WANT_SLN_ASSERTS
#define WANT_SLN_ASSERTS
#endif

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include "sln_types.h"
#include "sln_assert.h"
#include "cmockery.h"

#ifdef SLN_TEST_ALL
#define SLN_TESTS_START(module) \
  int sln_tests_##module() {    \
    int rv = 0;                 \
  const UnitTest tests[] = {

#define SLN_TESTS_ENTRY(entry) unit_test(entry),

#define SLN_TESTS_END()  \
  }                      \
  ;                      \
  rv = run_tests(tests); \
  return rv;             \
  }

#else

#define SLN_TESTS_START(module)      \
  int main(int argc, char *argv[]) { \
  const UnitTest tests[] = {

#define SLN_TESTS_ENTRY(entry) unit_test(entry),

#define SLN_TESTS_END()    \
  }                        \
  ;                        \
  sln_tests_setup();       \
  return run_tests(tests); \
  }
#endif

#undef SLN_ASSERT
#define SLN_ASSERT(expression) \
  mock_assert((int)(expression), #expression, __FILE__, __LINE__);

#undef SLN_ERR
#define SLN_ERR(expression)                                                \
  do {                                                                     \
    selene_error_t *selene__xx__err = (expression);                        \
    if (selene__xx__err != SELENE_SUCCESS) {                               \
      fprintf(stderr, "fatal error: (%d) %s from %s:%d caught at %s:%d\n", \
              selene__xx__err->err, selene__xx__err->msg,                  \
              selene__xx__err->file, selene__xx__err->line, __FILE__,      \
              __LINE__);                                                   \
    }                                                                      \
    mock_assert((int)(selene__xx__err == SELENE_SUCCESS), #expression,     \
                __FILE__, __LINE__);                                       \
  } while (0)

#define SLN_FAIL(expression)                                        \
  do {                                                              \
    selene_error_t *selene__xx__err;                                \
    /* TODO: print the error in test case mode */                   \
    SLN_ASSERT((selene__xx__err = (expression)) != SELENE_SUCCESS); \
  } while (0)

#define SLN_TEST_MODULE(name) int sln_tests_##name();

SLN_TEST_MODULE(arrays)
SLN_TEST_MODULE(logging)
SLN_TEST_MODULE(crypto_digest)
SLN_TEST_MODULE(crypto_prf)
SLN_TEST_MODULE(init)
SLN_TEST_MODULE(brigade)
SLN_TEST_MODULE(buckets)
SLN_TEST_MODULE(events)
SLN_TEST_MODULE(certs)
SLN_TEST_MODULE(tok)
SLN_TEST_MODULE(tls_io)
SLN_TEST_MODULE(handshake_io)
SLN_TEST_MODULE(alert_io)
SLN_TEST_MODULE(loopback)

selene_alloc_t *sln_test_alloc;

#define PATHMAX 1024
extern char executable_path[PATHMAX];
extern char testdir_path[PATHMAX];
void sln_tests_setup();

const char *sln_tests_load_cert(const char *fname);

#endif
