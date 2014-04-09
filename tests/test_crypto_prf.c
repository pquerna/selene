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
#include "sln_tests.h"
#include "sln_types.h"
#include "sln_prf.h"
#include <string.h>

unsigned char ssl_test_vector[] = {0xb5, 0xba, 0xf4, 0x72, 0x2b, 0x91, 0x85,
                                   0x1a, 0x88, 0x16, 0xd2, 0x2e, 0xbd, 0x8c,
                                   0x1d, 0x8c, 0xa0, 0x33, 0x25, 0x85};

static void prf_vector_from_book(void **state) {
  selene_conf_t *conf = NULL;
  selene_t *s = NULL;
  char buf[20];

  selene_conf_create(&conf);
  SLN_ERR(selene_conf_use_reasonable_defaults(conf));
  SLN_ERR(selene_server_create(conf, &s));
  SLN_ASSERT_CONTEXT(s);

  /**
   * Test vector from Implementing SSL/TLS....
   * inputs: secret label seed 20
   * output: b5baf4722b91851a8816d22ebd8c1d8cc2e94d55
   */
  SLN_ERR(sln_prf(s, "label", strlen("label"), "secret", strlen("secret"),
                  "seed", strlen("seed"), buf, sizeof(buf)));

  assert_memory_equal(buf, ssl_test_vector, 20);

  selene_destroy(s);
  selene_conf_destroy(conf);
}

SLN_TESTS_START(crypto_prf)
SLN_TESTS_ENTRY(prf_vector_from_book)
SLN_TESTS_END()
