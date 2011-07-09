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
 * @file selene.h
 */

#include <stdlib.h> /* for size_t */
#include <sys/socket.h> /* for iovec */

#include "selene_visibility.h"
#include "selene_version.h"
#include "selene_error.h"
#include "selene_conf.h"

#ifndef _selene_h_
#define _selene_h_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Opaque context of an SSL/TLS Session */
typedef struct selene_t selene_t;

#include "selene_cert.h"

/**
 * Creates a Client SSL/TLS Context.
 */
SELENE_API(selene_error_t*) selene_client_create(selene_conf_t *conf, selene_t **ctxt);

/**
 * Creates a Server SSL/TLS Context.
 */
SELENE_API(selene_error_t*) selene_server_create(selene_conf_t *conf, selene_t **ctxt);

/**
 * Destroys a SSL/TLS Context of any type.  After this
 * call, ctxt points to invalid memory and should not be used.
 */
SELENE_API(void) selene_destroy(selene_t *ctxt);

/**
 * Starts processing, call after you have Subscribed to events,
 * and set any options on a created context.
 */
SELENE_API(selene_error_t*) selene_start(selene_t *ctxt);

/* (client only) Set Server name indication extension. Must be called before selene_start. */
SELENE_API(selene_error_t*)
selene_client_name_indication(selene_t *ctxt, const char* sni);

/* (client only) Add a protocol to the next protocol negotiation list, like 
 *  'spdy/2' or 'http/1.1'. Must be called before selene_start. */
SELENE_API(selene_error_t*)
selene_client_next_protocol_add(selene_t *ctxt, const char* protocol);


/* Possible Event Types */
typedef enum {
  SELENE_EVENT__UNUSED0 = 0,
  /* Called when Selene's need to read or write data has changed */
  SELENE_EVENT_IOWANT_CHANGED = 1,
  SELENE_EVENT_IO_IN_ENC = 2,
  SELENE_EVENT_IO_OUT_ENC = 3,
  SELENE_EVENT_IO_IN_CLEAR = 4,
  SELENE_EVENT_IO_OUT_CLEAR = 5,
  SELENE_EVENT_LOG_MSG = 6,
  /* The first bytes of our TLS data looked like an HTTP request, maybe send
   * your client a nice error message? */
  SELENE_EVENT_TLS_GOT_HTTP = 7,
  /* INTERNAL: When we recieved a properly formed client hello */
  SELENE__EVENT_HS_GOT_CLIENT_HELLO = 8,
  SELENE__EVENT_HS_GOT_SERVER_HELLO = 9,
  SELENE__EVENT_HS_GOT_CERTIFICATE = 10,
  SELENE__EVENT_HS_GOT_SERVER_HELLO_DONE = 11,
  SELENE_EVENT_VALIDATE_CERTIFICATE = 12,
  SELENE_EVENT__MAX = 13
} selene_event_e;

typedef enum {
  SELENE_IOWANT__UNUSED0 = 0,
  SELENE_IOWANT_READ = (1U<<1),
  SELENE_IOWANT_WRITE = (1U<<2),
  SELENE_IOWANT__MAX = (1U<<3)
} selene_iowant_e;

typedef selene_error_t* (selene_event_cb)(selene_t *ctxt,
                                          selene_event_e event,
                                          void *baton);

/**
 * Register to be the single Handler for an Event.
 *
 * Handlers are used to allow plugable backends for many tasks, but
 * for which you only want one answer.  Verification of a Certificate
 * chain is a good example.
 *
 * Depending on the Event Type, you may be asked to call other functions
 * on success or failure -- see the documenation about a specific event
 * for details.
 */
SELENE_API(selene_error_t*) selene_handler_set(selene_t *ctxt,
                                               selene_event_e event,
                                               selene_event_cb cb,
                                               void *baton);
/**
 * Subscribe to an Event.
 */
SELENE_API(selene_error_t*) selene_subscribe(selene_t *ctxt,
                                             selene_event_e event,
                                             selene_event_cb cb,
                                             void *baton);
/**
 * Removes Subscribtion to an Event, searching for both a matching cb and baton.
 */
SELENE_API(selene_error_t*) selene_unsubscribe(selene_t *ctxt,
                                               selene_event_e event,
                                               selene_event_cb cb,
                                               void *baton);
/**
 * Publishes an event. Note that this is used by the internals of 
 * the library to do its own processing, so don't blindly publish
 * events.
 */
SELENE_API(selene_error_t*) selene_publish(selene_t *ctxt,
                                           selene_event_e event);

/* maybe not temp api*/
SELENE_API(selene_error_t*) selene_io_want(selene_t *ctxt, selene_iowant_e *want);

/* Hand cleartext bytes to Selene */
SELENE_API(selene_error_t*)
selene_io_in_clear_bytes(selene_t *ctxt,
                         const char* bytes,
                         size_t length);

SELENE_API(selene_error_t*)
selene_io_in_clear_iovec(selene_t *s,
                          const struct iovec *vec,
                          int iovcnt);

/* Hand encrypted input bytes to Selene */
SELENE_API(selene_error_t*)
selene_io_in_enc_bytes(selene_t *ctxt,
                       const char* bytes,
                       size_t length);

/* Read cleartext bytes out of Selene and parse by your application */
SELENE_API(selene_error_t*)
selene_io_out_clear_bytes(selene_t *ctxt,
                          char* buffer,
                          size_t blen,
                          size_t *length,
                          size_t *remaining);


/* Take encrypted bytes out of Selene, and send to the destination */
SELENE_API(selene_error_t*)
selene_io_out_enc_bytes(selene_t *ctxt,
                        char* buffer,
                        size_t blen,
                        size_t *length,
                        size_t *remaining);


SELENE_API(void)
selene_log_msg_get(selene_t *ctxt, const char **log_msg,
                   size_t *log_msg_len);

/**
 * May return NULL until SELENE_EVENT_VALIDATE_CERTIFICATE event has fired.
 */
SELENE_API(selene_cert_chain_t*)
selene_peer_certchain(selene_t *ctxt);

/**
 * Mark a the peer cert chain as trusted (1) or untrusted (0).  Must be called for
 * SELENE_EVENT_VALIDATE_CERTIFICATE event to complete.  If untrusted,
 * a TLS alert will be sent, and the connection will be closed.
 */
SELENE_API(void)
selene_complete_peer_certchain_validated(selene_t *ctxt, int valid);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _selene_h_ */
