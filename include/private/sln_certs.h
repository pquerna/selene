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

#ifndef _sln_certs_h_
#define _sln_certs_h_

#include "selene.h"
#include "sln_types.h"

int64_t
sln_asn1_time_to_timestamp(ASN1_TIME *as);

selene_error_t*
sln_cert_create(selene_conf_t *conf, X509 *x509, int depth, selene_cert_t **p_cert);

void
sln_cert_destroy(selene_cert_t *cert);

selene_error_t*
sln_cert_chain_create(selene_conf_t *conf, selene_cert_chain_t **out_cc);

void
sln_cert_chain_destroy(selene_conf_t *conf, selene_cert_chain_t *chain);

void
sln_cert_chain_clear(selene_conf_t *conf, selene_cert_chain_t *chain);

#define SLN_CERT_REMOVE(e) SLN_RING_REMOVE((e), link)

#define SLN_CERT_CHAIN_SENTINEL(b) SLN_RING_SENTINEL(&(b)->list, selene_cert_t, link)
#define SLN_CERT_CHAIN_EMPTY(b) SLN_RING_EMPTY(&(b)->list, selene_cert_t, link)
#define SLN_CERT_CHAIN_FIRST(b) SLN_RING_FIRST(&(b)->list)
#define SLN_CERT_CHAIN_LAST(b) SLN_RING_LAST(&(b)->list)

#ifdef SLN_CERT_CHAIN_DEBUG
#define SLN_CERT_CHAIN_CHECK_CONSISTENCY(b) \
  do { \
    SLN_RING_CHECK_CONSISTENCY(&(b)->list, selene_cert_t, link); \
  } while (0)
#else
#define SLN_CERT_CHAIN_CHECK_CONSISTENCY(b)
#endif

#define SLN_CERT_CHAIN_INSERT_TAIL(cc, e) \
  do { \
    selene_cert_t *sln__c = (e); \
    SLN_RING_INSERT_TAIL(&(cc)->list, sln__c, selene_cert_t, link); \
    SLN_CERT_CHAIN_CHECK_CONSISTENCY((cc)); \
  } while (0)

#endif
