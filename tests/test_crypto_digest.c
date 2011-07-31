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
#include "sln_digest.h"
#include <string.h>

static struct {
    const char *string;
    const char *digest;
} md5sums[] = 
{
    {"Jeff was here!",
     "\xa5\x25\x8a\x89\x11\xb2\x9d\x1f\x81\x75\x96\x3b\x60\x94\x49\xc0"},
    {"01234567890aBcDeFASDFGHJKLPOIUYTR"
     "POIUYTREWQZXCVBN  LLLLLLLLLLLLLLL",
     "\xd4\x1a\x06\x2c\xc5\xfd\x6f\x24\x67\x68\x56\x7c\x40\x8a\xd5\x69"},
    {"111111118888888888888888*******%%%%%%%%%%#####"
     "142134u8097289720432098409289nkjlfkjlmn,m..   ",
     "\xb6\xea\x5b\xe8\xca\x45\x8a\x33\xf0\xf1\x84\x6f\xf9\x65\xa8\xe1"},
    {"01234567890aBcDeFASDFGHJKLPOIUYTR"
     "POIUYTREWQZXCVBN  LLLLLLLLLLLLLLL"
     "01234567890aBcDeFASDFGHJKLPOIUYTR"
     "POIUYTREWQZXCVBN  LLLLLLLLLLLLLLL"
     "1",
     "\xd1\xa1\xc0\x97\x8a\x60\xbb\xfb\x2a\x25\x46\x9d\xa5\xae\xd0\xb0"}
};

static int num_md5_sums = sizeof(md5sums) / sizeof(md5sums[0]);

static void
digest_md5_iter(void **state, int count)
{
  selene_conf_t *conf = NULL;
  selene_t *s = NULL;
  unsigned char digest[SLN_MD5_DIGEST_LENGTH];
  const void *string = md5sums[count].string;
  const void *sum = md5sums[count].digest;
  unsigned int len = strlen(string);
  sln_digest_t *d;

  selene_conf_create(&conf);
  SLN_ERR(selene_conf_use_reasonable_defaults(conf));
  SLN_ERR(selene_server_create(conf, &s));
  SLN_ASSERT_CONTEXT(s);

#ifdef SLN_HAVE_OSX_COMMONCRYPTO
  memset(digest, 0, SLN_MD5_DIGEST_LENGTH);

  SLN_ERR(sln_digest_osx_cc_create(s, SLN_DIGEST_MD5, &d));
  sln_digest_osx_cc_update(d, string, len);
  sln_digest_osx_cc_final(d, digest);
  sln_digest_osx_cc_destroy(d);
  assert_memory_equal(digest, sum, SLN_MD5_DIGEST_LENGTH);
#endif

  memset(digest, 0, SLN_MD5_DIGEST_LENGTH);

  SLN_ERR(sln_digest_openssl_create(s, SLN_DIGEST_MD5, &d));
  sln_digest_openssl_update(d, string, len);
  sln_digest_openssl_final(d, digest);
  sln_digest_openssl_destroy(d);
  assert_memory_equal(digest, sum, SLN_MD5_DIGEST_LENGTH);

  selene_destroy(s);
  selene_conf_destroy(conf);
}

static void
digest_md5(void **state)
{
  int i;

  for (i = 0; i < num_md5_sums; i++) {
    digest_md5_iter(state, i);
  }
}

SLN_TESTS_START(crypto_digest)
  SLN_TESTS_ENTRY(digest_md5)
SLN_TESTS_END()
