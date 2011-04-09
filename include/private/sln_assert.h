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

#ifndef _sln_assert_h_
#define _sln_assert_h_

#if defined(DEBUG) || defined(UNIT_TESTING)
/* TODO: move to scons */
#ifndef WANT_SLN_ASSERTS
#define WANT_SLN_ASSERTS
#endif
#endif

#ifdef WANT_SLN_ASSERTS

  #include <assert.h>

  #define SLN_ASSERT(exp) assert(exp)

  #define SLN_ASSERT_RANGE(start, end, target) SLN_ASSERT(target > start); SLN_ASSERT(target < end);

  #define SLN_ASSERT_ENUM(type, target) SLN_ASSERT_RANGE(type ## __UNUSED0, type ## __MAX, target)

  #define SLN_ASSERT_FLAGS(type, value) SLN_ASSERT((type & (value)) == 0)

  #define SLN_ASSERT_CONF(conf) do { \
    SLN_ASSERT(conf != NULL); \
    /* TODO: this isn't good, need to improve */ \
    SLN_ASSERT_FLAGS(conf->ciphers, SELENE_CS_RSA_WITH_RC4_128_SHA|SELENE_CS_RSA_WITH_AES_128_CBC_SHA|SELENE_CS_RSA_WITH_AES_256_CBC_SHA); \
    SLN_ASSERT_FLAGS(conf->protocols, SELENE_PROTOCOL_SSL30|SELENE_PROTOCOL_TLS10|SELENE_PROTOCOL_TLS11|SELENE_PROTOCOL_TLS12); \
  } while (0);

  #define SLN_ASSERT_CONTEXT(ctxt) do { \
    SLN_ASSERT(ctxt != NULL); \
    SLN_ASSERT_CONF(ctxt->conf); \
    SLN_ASSERT_ENUM(SLN_STATE, ctxt->state); \
    SLN_ASSERT_ENUM(SLN_LOG, ctxt->log_level); \
    SLN_ASSERT(ctxt->log_msg_len >= 0); \
    SLN_ASSERT(ctxt->log_msg_len <= 2048); \
    SLN_ASSERT_ENUM(SLN_LOG, ctxt->log_msg_level); \
  } while (0);

#else /* !WANT_SLN_ASSERTS */

  #define SLN_ASSERT(exp)

  #define SLN_ASSERT_RANGE(start, end, target)

  #define SLN_ASSERT_ENUM(type, target)

  #define SLN_ASSERT_CONF(conf)

  #define SLN_ASSERT_CONTEXT(ctxt)

#endif

#endif
