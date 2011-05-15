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

#include "native.h"
#include "alert_messages.h"
#include "sln_tok.h"

static selene_error_t *
sln_native_io_alert(selene_t *s, sln_alert_level_e level, sln_alert_description_e desc)
{
  selene_error_t *err;
  sln_bucket_t *btls = NULL;
  sln_bucket_t *balert = NULL;
  sln_msg_alert_t alert;
  sln_native_msg_tls_t tls;

  alert.level =  level;
  alert.description = desc;

  SELENE_ERR(sln_native_alert_unparse(&alert, &balert));

  if (err) {
    return err;
  }

  tls.content_type = SLN_NATIVE_CONTENT_TYPE_ALERT;
  tls.version_major = 3;
  tls.version_minor = 1;
  tls.length = balert->size;

  SELENE_ERR(sln_tls_unparse_header(&tls, &btls));

  SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, btls);

  SLN_BRIGADE_INSERT_TAIL(s->bb.out_enc, balert);

  return err;
}

selene_error_t *
sln_native_io_alert_fatal(selene_t *s, sln_alert_description_e desc)
{
  return sln_native_io_alert(s, SLN_ALERT_LEVEL_FATAL, desc);
}

selene_error_t *
sln_native_io_alert_warning(selene_t *s, sln_alert_description_e desc)
{
  return sln_native_io_alert(s, SLN_ALERT_LEVEL_WARNING, desc);
}


selene_error_t*
sln_native_io_alert_read(selene_t *s, sln_native_baton_t *baton)
{
  sln_alert_baton_t ab;

  ab.s = s;
  ab.baton = baton;
  ab.state = SLN_ALERT_STATE__INIT;

  sln_tok_parser(baton->in_alert, sln_native_alert_parse, &ab);

  if (ab.state == SLN_ALERT_STATE__DONE) {
    /* TODO: emit event for alert */
    /* TODO: handle close notify */
  }

  return SELENE_SUCCESS;
}
