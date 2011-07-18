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

/**
 * @file selene_conf.h
 */

#include "selene_visibility.h"
#include "selene_error.h"

#ifndef _selene_conf_h_
#define _selene_conf_h_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Opaque context for configuring many SSL/TLS sessions. */
typedef struct selene_conf_t selene_conf_t;

typedef void* (selene_malloc_cb)(void *baton, size_t len);
typedef void (selene_free_cb)(void *baton, void *ptr);

typedef struct selene_alloc_t {
  /* Baton passed into all memory operations */
  void *baton;
  /* Allocate uninitizlized memory */
  selene_malloc_cb *malloc;
  /* Allocate memory set to zero */
  selene_malloc_cb *calloc;
  /* Free a previosly allocated memory block */
  selene_free_cb *free;
} selene_alloc_t;

/**
 * Creates a configuration context.
 */
SELENE_API(selene_error_t*) selene_conf_create(selene_conf_t **conf);

/**
 * Creates a configuration context, with a specified memory allocator
 */
SELENE_API(selene_error_t*) selene_conf_create_with_alloc(selene_conf_t **conf, selene_alloc_t *alloc);

/**
 * Destroy a configuration context.
 */
SELENE_API(void) selene_conf_destroy(selene_conf_t *conf);

/* Uses reasonable and sane defaults for all configuration options */
SELENE_API(selene_error_t*)
selene_conf_use_reasonable_defaults(selene_conf_t *conf);

typedef enum {
  SELENE_COMP__UNUSED0 = 0,
  SELENE_COMP_NULL = 1,
  SELENE_COMP_DEFLATE = 2,
  SELENE_COMP__MAX = 3
} selene_compression_method_e;

typedef enum {
  SELENE_CS__UNUSED0 = 0,
  SELENE_CS_RSA_WITH_RC4_128_SHA = 1,
  SELENE_CS_RSA_WITH_AES_128_CBC_SHA = 2,
  SELENE_CS_RSA_WITH_AES_256_CBC_SHA = 3,
  SELENE_CS__MAX = 4
} selene_cipher_suite_e;

typedef struct selene_cipher_suite_list_t selene_cipher_suite_list_t;

/**
 * Creates an ordered list of Cipher Suites.
 */
SELENE_API(selene_error_t*) selene_cipher_suite_list_create(selene_alloc_t *alloc, selene_cipher_suite_list_t **ciphers);

/**
 * Add a single cipher suite to the list.
 */
SELENE_API(selene_error_t*) selene_cipher_suite_list_add(selene_cipher_suite_list_t *ciphers, selene_cipher_suite_e suite);

/**
 * Destroys the list of Cipher Suites
 */
SELENE_API(void) selene_cipher_suite_list_destroy(selene_cipher_suite_list_t *ciphers);

/**
 * Configures a configuration context with a set of cipher suites.  The information is copied,
 * so you retain ownership of the selene_cipher_suite_list_tn object.
 */
SELENE_API(selene_error_t*)
selene_conf_cipher_suites(selene_conf_t *conf, selene_cipher_suite_list_t *cl);

typedef enum {
  SELENE_PROTOCOL__UNUSED0 = 0,
  SELENE_PROTOCOL_SSL30 = (1U<<1),
  SELENE_PROTOCOL_TLS10 = (1U<<2),
  SELENE_PROTOCOL_TLS11 = (1U<<3),
  SELENE_PROTOCOL_TLS12 = (1U<<4),
  SELENE_PROTOCOL__MAX = (1U<<5)
} selene_protocol_e;

SELENE_API(selene_error_t*)
selene_conf_protocols(selene_conf_t *conf, int protocols);

/* TODO: this is a OpenSSL specific interface*/
#if 0
SELENE_API(selene_error_t*)
selene_conf_crypto_device(selene_conf_t *cont, const char* name);
#endif

/* Set the Certificate chain for the server to use.  If you
 * need a chain certificate, just append it to your
 * certifcate. (server only)
 *
 * The private key will be associated with this chain.
 */
SELENE_API(selene_error_t*)
selene_conf_cert_chain_add(selene_conf_t *conf, const char *certificates, const char* private_key);

/**
 * Add a CA certificate to the list of all trusted certificates.
 * Currently, once added, it cannot be removed from the conf_t.
 *
 * For the client, these certificates will be used to validate the server certificate.
 *
 * For the server, these certificates will be used validate client certificates, if
 * configured.
 */
SELENE_API(selene_error_t*)
selene_conf_ca_trusted_cert_add(selene_conf_t *conf, const char *certificate);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _selene_conf_h_ */
