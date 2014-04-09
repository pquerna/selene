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

#include "parser.h"
#include "alert_messages.h"

selene_error_t *sln_alert_serialize(selene_t *s, sln_msg_alert_t *alert,
                                    sln_bucket_t **p_b) {
  sln_bucket_t *b = NULL;
  size_t len = 2;

  sln_bucket_create_empty(s->alloc, &b, len);

  b->data[0] = alert->level;
  b->data[1] = alert->description;

  *p_b = b;

  return SELENE_SUCCESS;
}

static int is_valid_alert_level(int level) {
  if (level == SLN_ALERT_LEVEL_WARNING || level == SLN_ALERT_LEVEL_FATAL) {

    return 1;
  }

  return 0;
}

static int is_valid_alert_description(int desc) {
  if (desc == SLN_ALERT_DESC_CLOSE_NOTIFY ||
      desc == SLN_ALERT_DESC_UNEXPECTED_MESSAGE ||
      desc == SLN_ALERT_DESC_BAD_RECORD_MAC ||
      desc == SLN_ALERT_DESC_RESERVED_DECRYPTION_FAILED ||
      desc == SLN_ALERT_DESC_RECORD_OVERFLOW ||
      desc == SLN_ALERT_DESC_DECOMPRESSION_FAILURE ||
      desc == SLN_ALERT_DESC_HANDSHAKE_FAILURE ||
      desc == SLN_ALERT_DESC_RESERVED_NO_CERTIFICATE ||
      desc == SLN_ALERT_DESC_BAD_CERTIFICATE ||
      desc == SLN_ALERT_DESC_UNSUPPORTED_CERTIFICATE ||
      desc == SLN_ALERT_DESC_CERTIFICATE_REVOKED ||
      desc == SLN_ALERT_DESC_CERTIFICATE_EXPIRED ||
      desc == SLN_ALERT_DESC_CERTIFICATE_UNKNOWN ||
      desc == SLN_ALERT_DESC_ILLEGAL_PARAMETER ||
      desc == SLN_ALERT_DESC_UNKNOWN_CA ||
      desc == SLN_ALERT_DESC_ACCESS_DENIED ||
      desc == SLN_ALERT_DESC_DECODE_ERROR ||
      desc == SLN_ALERT_DESC_DECRYPT_ERROR ||
      desc == SLN_ALERT_DESC_RESERVED_EXPORT_RESTRICTION ||
      desc == SLN_ALERT_DESC_PROTOCOL_VERSION ||
      desc == SLN_ALERT_DESC_INSUFFICENT_SECURITY ||
      desc == SLN_ALERT_DESC_INTERNAL_ERROR ||
      desc == SLN_ALERT_DESC_USER_CANCELED ||
      desc == SLN_ALERT_DESC_NO_RENEGOTIATION ||
      desc == SLN_ALERT_DESC_UNSUPPORTED_EXTENSION) {

    return 1;
  }

  return 0;
}

selene_error_t *sln_alert_parse(sln_tok_value_t *v, void *baton_) {
  selene_error_t *err = SELENE_SUCCESS;
  sln_alert_baton_t *ab = (sln_alert_baton_t *)baton_;

  switch (ab->state) {
    case SLN_ALERT_STATE__INIT:
      ab->state = SLN_ALERT_STATE_LEVEL;
      v->next = TOK_COPY_BYTES;
      v->wantlen = 1;
      break;
    case SLN_ALERT_STATE_LEVEL:
      ab->alert->level = v->v.bytes[0];
      if (!is_valid_alert_level(ab->alert->level)) {
        err = selene_error_createf(SELENE_EINVAL, "Invalid alert level: %u",
                                   ab->alert->level);
      } else {
        ab->state = SLN_ALERT_STATE_DESCRIPTION;
        v->next = TOK_COPY_BYTES;
        v->wantlen = 1;
      }
      break;
    case SLN_ALERT_STATE_DESCRIPTION:
      ab->alert->description = v->v.bytes[0];
      if (!is_valid_alert_description(ab->alert->description)) {
        /* if we get an unkown alert desc, we are going to force are
         * connection to abort to be paranoid, but leave the value in there (?)
         */
        ab->alert->level = SLN_ALERT_LEVEL_FATAL;
      }
      ab->state = SLN_ALERT_STATE__DONE;
      v->next = TOK_DONE;
      v->wantlen = 0;
      break;
    default:
      ab->state = SLN_ALERT_STATE__DONE;
      v->next = TOK_DONE;
      v->wantlen = 0;
  }
  return err;
}
