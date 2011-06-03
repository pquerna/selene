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

#ifndef _alert_messages_h_
#define _alert_messages_h_

#include "sln_tok.h"

typedef enum sln_alert_level_e {
  SLN_ALERT_LEVEL_WARNING = 1,
  SLN_ALERT_LEVEL_FATAL = 2,
} sln_alert_level_e;

typedef enum sln_alert_description_e {
  SLN_ALERT_DESC_CLOSE_NOTIFY = 0,
  SLN_ALERT_DESC_UNEXPECTED_MESSAGE = 10,
  SLN_ALERT_DESC_BAD_RECORD_MAC = 20,
  SLN_ALERT_DESC_RESERVED_DECRYPTION_FAILED = 21,
  SLN_ALERT_DESC_RECORD_OVERFLOW = 22,
  SLN_ALERT_DESC_DECOMPRESSION_FAILURE = 30,
  SLN_ALERT_DESC_HANDSHAKE_FAILURE = 40,
  SLN_ALERT_DESC_RESERVED_NO_CERTIFICATE = 41,
  SLN_ALERT_DESC_BAD_CERTIFICATE = 42,
  SLN_ALERT_DESC_UNSUPPORTED_CERTIFICATE = 43,
  SLN_ALERT_DESC_CERTIFICATE_REVOKED = 44,
  SLN_ALERT_DESC_CERTIFICATE_EXPIRED = 45,
  SLN_ALERT_DESC_CERTIFICATE_UNKNOWN = 46,
  SLN_ALERT_DESC_ILLEGAL_PARAMETER = 47,
  SLN_ALERT_DESC_UNKNOWN_CA = 48,
  SLN_ALERT_DESC_ACCESS_DENIED = 49,
  SLN_ALERT_DESC_DECODE_ERROR = 50,
  SLN_ALERT_DESC_DECRYPT_ERROR = 51,
  SLN_ALERT_DESC_RESERVED_EXPORT_RESTRICTION = 60,
  SLN_ALERT_DESC_PROTOCOL_VERSION = 70,
  SLN_ALERT_DESC_INSUFFICENT_SECURITY = 71,
  SLN_ALERT_DESC_INTERNAL_ERROR = 80,
  SLN_ALERT_DESC_USER_CANCELED = 90,
  SLN_ALERT_DESC_NO_RENEGOTIATION = 100,
  SLN_ALERT_DESC_UNSUPPORTED_EXTENSION = 110,
} sln_alert_description_e;

typedef enum sln_alert_state_e {
  SLN_ALERT_STATE__UNUSED,
  SLN_ALERT_STATE__INIT,
  SLN_ALERT_STATE_LEVEL,
  SLN_ALERT_STATE_DESCRIPTION,
  SLN_ALERT_STATE__DONE,
  SLN_ALERT_STATE__MAX,
} sln_alert_state_e;

typedef struct sln_msg_alert_t {
  sln_alert_level_e level;
  sln_alert_description_e description;
} sln_msg_alert_t;

typedef struct sln_alert_baton_t {
  selene_t *s;
  sln_parser_baton_t *baton;
  sln_alert_state_e state;
  sln_msg_alert_t *alert;
} sln_alert_baton_t;

selene_error_t*
sln_alert_unparse(selene_t *s, sln_msg_alert_t *alert, sln_bucket_t **p_b);

selene_error_t*
sln_io_alert_fatal(selene_t *s, sln_alert_description_e desc);

selene_error_t*
sln_io_alert_warning(selene_t *s, sln_alert_description_e desc);

selene_error_t*
sln_alert_parse(sln_tok_value_t *v, void *baton_);
  
#endif
