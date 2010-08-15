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

#ifndef _selene_h_
#define _selene_h_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdlib.h>
#include "selene_visibility.h"
#include "selene_version.h"
#include "selene_error.h"

/** Opaque context of an SSL/TLS Session */
typedef struct selene_t selene_t;

/**
 * Creates a Client SSL/TLS Context.
 */
SELENE_API(selene_error_t*) selene_client_create(selene_t **ctxt);

/**
 * Creates a Server SSL/TLS Context.
 */
SELENE_API(selene_error_t*) selene_server_create(selene_t **ctxt);

/**
 * Starts processing, call after you have Subscribed to events,
 * and set any options on a created context.
 */
SELENE_API(selene_error_t*) selene_start(selene_t *ctxt);

/**
 * Destroys a SSL/TLS Context of any type.  After this
 * call, ctxt points to invalid memory and should not be used.
 */
SELENE_API(void) selene_destroy(selene_t *ctxt);


/* Possible Event Types */
typedef enum {
  SELENE_EVENT__UNUSED0 = 0,
  /* Called when Selene's need to read or write data has changed */
  SELENE_EVENT_IOWANT_CHANGED = 1,
  SELENE_EVENT_IO_IN_ENC = 2,
  SELENE_EVENT_IO_OUT_ENC = 3,
  SELENE_EVENT_IO_IN_CLEAR = 4,
  SELENE_EVENT_IO_OUT_CLEAR = 5,
  SELENE_EVENT__MAX = 6,
} selene_event_e;

typedef enum {
  SELENE_IOWANT__UNUSED0 = 0,
  SELENE_IOWANT_READ = (1U<<1),
  SELENE_IOWANT_WRITE = (1U<<2),
  SELENE_IOWANT__MAX = (1U<<3),
} selene_iowant_e;

typedef selene_error_t* (selene_event_cb)(selene_t *ctxt,
                                          selene_event_e event,
                                          void *baton);

/**
 * Subscribe to an Event.
 */
SELENE_API(selene_error_t*) selene_subscribe(selene_t *ctxt,
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


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _selene_h_ */