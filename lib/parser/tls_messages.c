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
#include "common.h"

selene_error_t*
sln_tls_serialize_header(selene_t *s, sln_msg_tls_t *tls, sln_bucket_t **p_b)
{
  sln_bucket_t *b = NULL;
  
  size_t len = 5;

  sln_bucket_create_empty(s->alloc, &b, len);

  switch (tls->content_type) {
    case SLN_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
      b->data[0] = 0x14;
      break;
    case SLN_CONTENT_TYPE_ALERT:
      b->data[0] = 0x15;
      break;
    case SLN_CONTENT_TYPE_HANDSHAKE:
      b->data[0] = 0x16;
      break;
    case SLN_CONTENT_TYPE_APPLICATION:
      b->data[0] = 0x17;
      break;
    default:
      return selene_error_createf(SELENE_EINVAL,
                                  "Unknown content type: %d",
                                  tls->content_type);
  }

  b->data[1] = tls->version_major;
  b->data[2] = tls->version_minor;
  b->data[3] = tls->length >> 8;
  b->data[4] = tls->length;

  *p_b = b;

  return SELENE_SUCCESS;
}


selene_error_t*
sln_tls_toss_bucket(selene_t *s, sln_content_type_e content_type, sln_bucket_t *bout)
{
  sln_msg_tls_t tls;
  sln_bucket_t *btls = NULL;

  tls.content_type = content_type;
  sln_parser_tls_set_current_version(s, &tls.version_major, &tls.version_minor);
  tls.length = bout->size;

  SELENE_ERR(sln_tls_serialize_header(s, &tls, &btls));

  SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, btls);
  SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, bout);

  return SELENE_SUCCESS;
}
