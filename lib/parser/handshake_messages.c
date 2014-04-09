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

#include "sln_tok.h"
#include "parser.h"
#include "handshake_messages.h"

/* TODO: all other cipher suites */
selene_cipher_suite_e sln_parser_hs_bytes_to_cipher_suite(uint8_t first,
                                                          uint8_t second) {
  selene_cipher_suite_e suite = SELENE_CS__UNUSED0;
  switch (first) {
    case 0x00:
      switch (second) {
        case 0x05:
          suite = SELENE_CS_RSA_WITH_RC4_128_SHA;
          break;
        case 0x2F:
          suite = SELENE_CS_RSA_WITH_AES_128_CBC_SHA;
          break;
        case 0x35:
          suite = SELENE_CS_RSA_WITH_AES_256_CBC_SHA;
          break;
        default:
          break;
      }
      break;
    default:
      break;
  }

  return suite;
}

selene_compression_method_e sln_parser_hs_bytes_to_comp_method(uint8_t in) {
  selene_compression_method_e comp = SELENE_COMP_NULL;

  switch (in) {
    case 0:
      comp = SELENE_COMP_NULL;
      break;
    case 1:
      comp = SELENE_COMP_DEFLATE;
      break;
    default:
      /* TODO: fatal error? */
      break;
  }

  return comp;
}
