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

#include "../parser.h"
#include "../handshake_messages.h"
#include "sln_certs.h"
#include <string.h>

selene_error_t *sln_handshake_serialize_certificate(selene_t *s,
                                                    sln_msg_certificate_t *cert,
                                                    sln_bucket_t **p_b) {
  sln_bucket_t *b = NULL;
  size_t len = 0;
  size_t off;
  int dlen;
  int clen = 0;
  int num_certs = selene_cert_chain_count(cert->chain);
  int i;
  unsigned char *p;

  /* header size */
  len += 4;

  /* cert len */
  len += 3;

  /* length for each cert */
  len += 3 * num_certs;
  clen += 3 * num_certs;

  for (i = 0; i < num_certs; i++) {
    int l;
    selene_cert_t *c = selene_cert_chain_entry(cert->chain, i);
    /* the actual cert */
    l = i2d_X509(c->cert, NULL);
    len += l;
    clen += l;
  }

  sln_bucket_create_empty(s->alloc, &b, len);

  b->data[0] = SLN_HS_MT_CERTIFICATE;
  dlen = len - 4;
  b->data[1] = dlen >> 16;
  b->data[2] = dlen >> 8;
  b->data[3] = dlen;
  off = 4;

  b->data[off + 0] = clen >> 16;
  b->data[off + 1] = clen >> 8;
  b->data[off + 2] = clen;
  off += 3;

  for (i = 0; i < num_certs; i++) {
    selene_cert_t *c = selene_cert_chain_entry(cert->chain, i);
    size_t cert_len = i2d_X509(c->cert, NULL);

    b->data[off + 0] = cert_len >> 16;
    b->data[off + 1] = cert_len >> 8;
    b->data[off + 2] = cert_len;
    off += 3;

    p = (unsigned char *)&b->data[off + 0];
    i2d_X509(c->cert, &p);
    off += cert_len;
  }

  SLN_ASSERT(off == len);

  *p_b = b;

  return SELENE_SUCCESS;
}

typedef struct cert_baton_t {
  sln_handshake_certificate_state_e state;
  int certleft;
  int depth;
  sln_msg_certificate_t cert;
} cert_baton_t;

static selene_error_t *parse_certificate_step(sln_hs_baton_t *hs,
                                              sln_tok_value_t *v, void *baton) {
  selene_error_t *err = SELENE_SUCCESS;
  cert_baton_t *certb = (cert_baton_t *)baton;
  sln_msg_certificate_t *cert = &certb->cert;
  selene_t *s = hs->s;
  size_t l;

  switch (certb->state) {
    case SLN_HS_CERTIFICATE_LENGTH:
      certb->certleft = v->v.uint24;
      certb->depth = 0;
      certb->state = SLN_HS_CERTIFICATE_ENTRY_LENGTH;
      v->next = TOK_UINT24;
      v->wantlen = 3;
      slnDbg(s, "got total len: %d", certb->certleft);
      break;
    case SLN_HS_CERTIFICATE_ENTRY_LENGTH:
      certb->state = SLN_HS_CERTIFICATE_ENTRY_DATA;
      v->next = TOK_COPY_BRIGADE;
      v->wantlen = v->v.uint24;
      slnDbg(s, "cert want len: %d", (int)v->wantlen);
      certb->certleft -= v->v.uint24;
      slnDbg(s, "got total len left: %d", certb->certleft);
      break;
    case SLN_HS_CERTIFICATE_ENTRY_DATA: {
      const unsigned char *buf;
      const unsigned char *p;
      X509 *x509;

      slnDbg(s, "got cert data in brigade!");
      /* TODO: use a BIO here to avoid alloc */
      l = sln_brigade_size(v->v.bb);
      buf = sln_alloc(s, l);
      p = buf;
      err = sln_brigade_flatten(v->v.bb, (char *)buf, &l);

      if (err) {
        sln_free(s, (void *)buf);
        break;
      }

      /* TODO: certlist */
      x509 = d2i_X509(NULL, &p, l);
      /* TODO: error handling */
      if (x509 != NULL) {
        selene_cert_t *tmpc;
        slnDbg(s, "cert name: %s", x509->name);
        err = sln_cert_create(s->conf, x509, certb->depth, &tmpc);
        certb->depth++;
        if (err) {
          return err;
        }
        SLN_CERT_CHAIN_INSERT_TAIL(cert->chain, tmpc);
      }
      sln_free(s, (void *)buf);

      if (certb->certleft <= 0) {
        v->next = TOK_DONE;
        v->wantlen = 0;
        break;
      }
      certb->state = SLN_HS_CERTIFICATE_ENTRY_LENGTH;
      v->next = TOK_UINT24;
      v->wantlen = 3;
      break;
    }

    default:
      break;
  }

  return err;
}

static selene_error_t *parse_certificate_finish(sln_hs_baton_t *hs,
                                                void *baton) {
  return selene_publish(hs->s, SELENE__EVENT_HS_GOT_CERTIFICATE);
}

static void parse_certificate_destroy(sln_hs_baton_t *hs, void *baton) {
  cert_baton_t *certb = (cert_baton_t *)baton;
  if (certb->cert.chain != NULL) {
    sln_cert_chain_destroy(hs->s->conf, certb->cert.chain);
  }
  sln_free(hs->s, certb);
}

selene_error_t *sln_handshake_parse_certificate_setup(sln_hs_baton_t *hs,
                                                      sln_tok_value_t *v,
                                                      void **baton) {
  cert_baton_t *certb = sln_calloc(hs->s, sizeof(cert_baton_t));
  slnDbg(hs->s, "sln_handshake_parse_certificate_setup");
  sln_cert_chain_create(hs->s->conf, &certb->cert.chain);
  certb->state = SLN_HS_CERTIFICATE_LENGTH;
  hs->baton->msg.certificate = &certb->cert;
  hs->current_msg_step = parse_certificate_step;
  hs->current_msg_finish = parse_certificate_finish;
  hs->current_msg_destroy = parse_certificate_destroy;
  v->next = TOK_UINT24;
  v->wantlen = 3;
  *baton = (void *)certb;
  return SELENE_SUCCESS;
}
