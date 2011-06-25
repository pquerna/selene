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

#include "sln_brigades.h"
#include "parser.h"

selene_error_t*
sln_state_machine(selene_t *s, sln_parser_baton_t *baton)
{
  selene_error_t* err = SELENE_SUCCESS;

enter_state_machine:
  slnDbg(s, "enter handshake_state_machine=%d", baton->handshake);

  if (baton->connstate == SLN_CONNSTATE_ALERT_FATAL) {
    /* TODO: better error */
    slnDbg(s, "connection previously aborted");
    return baton->fatal_err;
  }

  if (!SLN_BRIGADE_EMPTY(s->bb.in_enc)) {
    slnDbg(s, "input tls brigade has content");
    err = sln_io_tls_read(s, baton);
    if (err) {
      return err;
    }
  }

  if (!SLN_BRIGADE_EMPTY(baton->in_alert)) {
    slnDbg(s, "input alert brigade has content");
    err = sln_io_alert_read(s, baton);
    if (err) {
      slnDbg(s, "got a tls alert error");
      return err;
    }
  }

  if (baton->ready_for_appdata && !SLN_BRIGADE_EMPTY(s->bb.in_cleartext)) {
    //err = sln_io_tls_write_appdata(s, baton);
    if (err) {
      return err;
    }
  }

  /* TODO: other connection states */
  if (baton->connstate == SLN_CONNSTATE_HANDSHAKE) {
    switch (baton->handshake) {
      case SLN_HANDSHAKE_CLIENT_SEND_HELLO:
        err = sln_io_handshake_client_hello(s, baton);
        if (err) {
          return err;
        }
        baton->handshake = SLN_HANDSHAKE_CLIENT_WAIT_SERVER_HELLO_DONE;
        goto enter_state_machine;
        break;
      case SLN_HANDSHAKE_CLIENT_WAIT_SERVER_HELLO_DONE:
        slnDbg(s, "trying server hello done");
        if (!SLN_BRIGADE_EMPTY(baton->in_handshake)) {
          slnDbg(s, "input handshake brigade has content");
          err = sln_io_handshake_read(s, baton);
          if (err) {
            return err;
          }
          if (baton->handshake != SLN_HANDSHAKE_CLIENT_WAIT_SERVER_HELLO_DONE) {
            goto enter_state_machine;
          }
        }
        break;
      case SLN_HANDSHAKE_CLIENT_SEND_FINISHED:
        break;
      case SLN_HANDSHAKE_CLIENT_WAIT_SERVER_FINISHED:
        break;
      case SLN_HANDSHAKE_CLIENT_APPDATA:
        break;

      /***
       * Start Server Methods.
       */
      case SLN_HANDSHAKE_SERVER_WAIT_CLIENT_HELLO:
        if (!SLN_BRIGADE_EMPTY(baton->in_handshake)) {
          err = sln_io_handshake_read(s, baton);
          if (err) {
            return err;
          }
          if (baton->handshake != SLN_HANDSHAKE_SERVER_WAIT_CLIENT_HELLO) {
            goto enter_state_machine;
          }
        }
        break;
      case SLN_HANDSHAKE_SERVER_SEND_SERVER_HELLO_DONE:
        break;
      case SLN_HANDSHAKE_SERVER_WAIT_CLIENT_FINISHED:
        break;
      case SLN_HANDSHAKE_SERVER_SEND_FINISHED:
        break;
      case SLN_HANDSHAKE_SERVER_APPDATA:
        break;

      case SLN_HANDSHAKE__UNUSED0:
      case SLN_HANDSHAKE__MAX:
        /* TODO: better handle this */
        abort();
        break;
      //default:
    }
  }

  if (!SLN_BRIGADE_EMPTY(s->bb.out_enc)) {
    slnDbg(s, "Encrypted data waiting");
    SELENE_ERR(selene_publish(s, SELENE_EVENT_IO_OUT_ENC));
  }

  if (!SLN_BRIGADE_EMPTY(s->bb.out_cleartext)) {
    slnDbg(s, "Cleartext data waiting");
    SELENE_ERR(selene_publish(s, SELENE_EVENT_IO_OUT_CLEAR));
  }

  slnDbg(s, "exit handshake_state_machine=%d", baton->handshake);
  return SELENE_SUCCESS;
}
