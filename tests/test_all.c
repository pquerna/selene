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
#include <stdio.h>

static void*
malloc_cb(void *baton, size_t len) {
  return malloc(len);
}

static void*
calloc_cb(void *baton, size_t len) {
  return calloc(1, len);
}

static void
free_cb(void *baton, void *ptr) {
  free(ptr);
}

static selene_alloc_t test_alloc = {
  NULL,
  malloc_cb,
  calloc_cb,
  free_cb
};

selene_alloc_t* sln_test_alloc = &test_alloc;

#define RUNT(module) do { \
    int rv = sln_tests_ ## module (); \
    if (rv != 0) { \
      return rv; \
    } \
  } while (0);

int main(int argc, char* argv[]) {

  sln_tests_setup();

  RUNT(logging);
  RUNT(init);
  RUNT(brigade);
  RUNT(buckets);
  RUNT(events);
  RUNT(certs);
  RUNT(tok);
  RUNT(tls_io);
  RUNT(handshake_io);
  RUNT(alert_io);
  RUNT(loopback);

  return 0;
}
