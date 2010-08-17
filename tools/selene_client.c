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

#include "selene.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>

/**
 * 'Simple' TLS Client, connects to a port, pipes stdin to it
 */
#define SERR(exp) do { \
    selene_error_t *SERR__err = NULL; \
    SERR__err = (exp); \
    if (SERR__err != SELENE_SUCCESS) { \
      fprintf(stderr, "[%s:%d] Selene Error: (%d) %s\n  Caught at: [%s:%d] %s", \
        SERR__err->file, SERR__err->line, SERR__err->err, SERR__err->msg, \
        __FILE__, __LINE__, \
        # exp ); \
      selene_error_clear(SERR__err); \
      return EXIT_FAILURE; \
    } \
  } while (0);

typedef struct {
  int sock;
  int write_err;
  int read_err;
} client_t;

static void
setblocking(int fd)
{
  int opts;
  opts = fcntl(fd, F_GETFL);
  opts = (opts ^ O_NONBLOCK);
  fcntl(fd, F_SETFL, opts);
}

static void
setnonblocking(int fd)
{
  int opts;
  opts = fcntl(fd, F_GETFL);
  opts = (opts | O_NONBLOCK);
  fcntl(fd, F_SETFL, opts);
}

static selene_error_t*
want_pull(selene_t *s, selene_event_e event, void *baton)
{
  int rv = 0;
  char buf[8096];
  size_t blen = 0;
  size_t remaining = 0;
  client_t *c = (client_t*) baton;

  do {
    SELENE_ERR(selene_io_out_enc_bytes(s,
                                 &buf[0], sizeof(buf),
                                 &blen, &remaining));

    if (blen > 0) {
      setblocking(c->sock);
      rv = write(c->sock, buf, blen);
      if (rv < 0) {
        c->write_err = errno;
        break;
      }
    }
  } while(remaining > 0);

  return SELENE_SUCCESS;
}

static int
read_from_sock(client_t *c, selene_t *s)
{
  int err;
  ssize_t rv = 0;
  do {
    char buf[8096];

    setnonblocking(c->sock);

    rv = read(c->sock, &buf[0], sizeof(buf));

    if (rv == -1) {
      err = errno;
      if (err != EAGAIN) {
        c->read_err = err;
        break;
      }
    }

    if (rv == 0) {
      break;
    }

    if (rv > 0) {
      SERR(selene_io_in_enc_bytes(s, buf, rv));
    }
  } while(rv > 0);

  return 0;
}

static int
connect_to(selene_t *s, const char *host, int port, FILE *fp)
{
  fd_set readers;
  int rv = 0;
  struct sockaddr_in addr;
  client_t client;
  char buf[8096];
  char *p = NULL;

  memset(&client, 0, sizeof(client));

  SERR(selene_subscribe(s, SELENE_EVENT_IO_OUT_ENC,
                        want_pull, &client));

  client.sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(host);
  addr.sin_port = htons(port);

  rv = connect(client.sock, (struct sockaddr *) &addr, sizeof(addr));

  if (rv != 0) {
    int err = errno;
    fprintf(stderr, "TCP connect(%s:%d) failed: (%d) %s\n",
            host, port,
            err, strerror(err));
    exit(EXIT_FAILURE);
  }

  SERR(selene_start(s));

  while (client.write_err == 0)
  {
    FD_ZERO(&readers);

    FD_SET(client.sock, &readers);
    FD_SET(fileno(stdin), &readers);

    rv = select(FD_SETSIZE, &readers, NULL, NULL, NULL);

    if (rv > 0) {
      if (FD_ISSET(fileno(stdin), &readers)) {
        p = fgets(buf, sizeof(buf), fp);

        if (p == NULL) {
          break;
        }

        SERR(selene_io_in_clear_bytes(s, p, strlen(p)));
      }
      else if (FD_ISSET(client.sock, &readers)) {
        read_from_sock(&client, s);
      }
    }
  }

  if (client.write_err != 0) {
    fprintf(stderr, "TCP write to %s:%d failed: (%d) %s\n",
            host, port,
            client.write_err, strerror(client.write_err));
    exit(EXIT_FAILURE);
  }

  if (client.read_err != 0) {
    fprintf(stderr, "TCP read from %s:%d failed: (%d) %s\n",
            host, port,
            client.read_err, strerror(client.read_err));
    exit(EXIT_FAILURE);
  }
  return 0;
}

int main(int argc, char* argv[])
{
  const char *host = NULL;
  int port = 0;
  selene_t *s = NULL;
  selene_error_t *err = NULL;
  int rv = 0;
  int i;

  err = selene_client_create(&s);
  if (err != SELENE_SUCCESS) {
    fprintf(stderr, "Failed to create client instance\n");
    exit(EXIT_FAILURE);
  }

  for (i = 1; i < argc; i++) {
    /* TODO: s_client compat */
    if (strcmp("-host", argv[i]) && argc > i + 1) {
      host = argv[i+1];
      i++;
    }
    else if (strcmp("-port", argv[i]) && argc > i + 1) {
      port = atoi(argv[i+1]);
      i++;
    }
    else {
      selene_destroy(s);
      fprintf(stderr, "Invalid args\n");
      exit(EXIT_FAILURE);
    }
  }

  if (host == NULL) {
    selene_destroy(s);
    fprintf(stderr, "-host must be set\n");
    exit(EXIT_FAILURE);
  }

  if (port == 0) {
    selene_destroy(s);
    fprintf(stderr, "-port must be set\n");
    exit(EXIT_FAILURE);
  }

  rv = connect_to(s, host, port, stdin);

  selene_destroy(s);

  return rv;
}
