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

#include "selene.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>

#define SELENE_SERVER_DEFAULT_HOST "localhost"
#define SELENE_SERVER_DEFAULT_PORT 4433
#define SELENE_SERVER_DEFAULT_CERT_PATH "server.pem"

/**
 * 'Simple' TLS Server, connects to a port, pipes stdin to it
 */
#define SERR(exp)                                                         \
  do {                                                                    \
    selene_error_t *SERR__err = NULL;                                     \
    SERR__err = (exp);                                                    \
    if (SERR__err != SELENE_SUCCESS) {                                    \
      fprintf(stderr,                                                     \
              "[%s:%d] Selene Error: (%d) %s\n  Caught at: [%s:%d] %s\n", \
              SERR__err->file, SERR__err->line, SERR__err->err,           \
              SERR__err->msg, __FILE__, __LINE__, #exp);                  \
      selene_error_clear(SERR__err);                                      \
      exit(EXIT_FAILURE);                                                 \
      return EXIT_FAILURE;                                                \
    }                                                                     \
  } while (0);

typedef struct {
  selene_t *s;
  int listen_sock;
  int sock;
  int write_err;
  int read_err;
} server_t;

static void setblocking(int fd) {
  int opts;
  opts = fcntl(fd, F_GETFL);
  opts = (opts ^ O_NONBLOCK);
  fcntl(fd, F_SETFL, opts);
}

static void setnonblocking(int fd) {
  int opts;
  opts = fcntl(fd, F_GETFL);
  opts = (opts | O_NONBLOCK);
  fcntl(fd, F_SETFL, opts);
}

static selene_error_t *have_logline(selene_t *s, selene_event_e event,
                                    void *baton) {
  const char *p = NULL;
  size_t len = 0;
  selene_log_msg_get(s, &p, &len);
  if (len > 0) {
    fwrite(p, len, 1, stderr);
    fflush(stderr);
  }
  return SELENE_SUCCESS;
}

static selene_error_t *have_cleartext(selene_t *s, selene_event_e event,
                                      void *baton) {
  char buf[8096];
  size_t blen = 0;
  size_t remaining = 0;

  do {
    SELENE_ERR(
        selene_io_out_clear_bytes(s, &buf[0], sizeof(buf), &blen, &remaining));

    if (blen > 0) {
      fwrite(buf, blen, 1, stdout);
      fflush(stdout);
    }
  } while (remaining > 0);

  return SELENE_SUCCESS;
}

static selene_error_t *want_pull(selene_t *s, selene_event_e event,
                                 void *baton) {
  int rv = 0;
  char buf[8096];
  size_t blen = 0;
  size_t remaining = 0;
  server_t *srv = (server_t *)baton;

  do {
    SELENE_ERR(
        selene_io_out_enc_bytes(s, &buf[0], sizeof(buf), &blen, &remaining));

    if (blen > 0) {
      setblocking(srv->sock);
      rv = write(srv->sock, buf, blen);
      if (rv < 0) {
        srv->write_err = errno;
        break;
      }
    }
  } while (remaining > 0);

  return SELENE_SUCCESS;
}

static int read_from_sock(server_t *srv) {
  selene_t *s = srv->s;
  int err;
  ssize_t rv = 0;
  do {
    char buf[8096];

    setnonblocking(srv->sock);

    rv = read(srv->sock, &buf[0], sizeof(buf));

    if (rv == -1) {
      err = errno;
      if (err != EAGAIN) {
        srv->read_err = err;
        break;
      }
    }

    if (rv == 0) {
      break;
    }

    if (rv > 0) {
      SERR(selene_io_in_enc_bytes(s, buf, rv));
    }
  } while (rv > 0);

  return 0;
}

static char *addr2str(struct sockaddr *sa, char *s, size_t maxlen) {
  switch (sa->sa_family) {
    case AF_INET:
      inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), s, maxlen);
      break;

    case AF_INET6:
      inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), s, maxlen);
      break;

    default:
      strncpy(s, "Unknown AF", maxlen);
      return NULL;
  }

  return s;
}
static int listen_to(selene_conf_t *conf, const char *host, int port,
                     FILE *fp) {
  fd_set readers;
  int rv = 0;
  int opt = 1;
  server_t server;
  char buf[8096];
  char port_str[16];
  char *p = NULL;
  struct addrinfo hints, *res, *res0;
  selene_error_t *err = NULL;
  char ip_buf[INET6_ADDRSTRLEN];
  char *ip_str = NULL;

  memset(&server, 0, sizeof(server));

  snprintf(port_str, sizeof(port_str), "%i", port);
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
  rv = getaddrinfo(host, port_str, &hints, &res0);
  if (rv != 0) {
    fprintf(stderr, "TCP getaddrinfo(%s:%d) failed: (%d) %s\n", host, port, rv,
            gai_strerror(rv));
    exit(EXIT_FAILURE);
  }

  server.sock = -1;
  for (res = res0; res; res = res->ai_next) {

    server.listen_sock =
        socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (server.listen_sock < 0) {
      continue;
    }

    ip_str = addr2str(res->ai_addr, &ip_buf[0], sizeof(ip_buf));

    fprintf(stderr, "TCP bind(%s:%d)\n", ip_str, port);

    rv = setsockopt(server.listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (rv != 0) {
      fprintf(stderr, "setsockopt failed: %s\n", strerror(errno));
      server.listen_sock = -1;
      continue;
    }

    rv = bind(server.listen_sock, res->ai_addr, res->ai_addrlen);
    if (rv != 0) {
      close(server.listen_sock);
      server.listen_sock = -1;
      continue;
    }

    rv = listen(server.listen_sock, 10);
    if (rv != 0) {
      close(server.listen_sock);
      server.listen_sock = -1;
      continue;
    }

    break;
  }

  freeaddrinfo(res0);

  if (server.listen_sock == -1) {
    fprintf(stderr, "TCP bind(%s:%d) failed\n", host, port);
    exit(EXIT_FAILURE);
  }

  server.sock = -1;

  while (server.write_err == 0) {
    FD_ZERO(&readers);

    FD_SET(server.listen_sock, &readers);
    if (server.sock != -1) {
      FD_SET(server.sock, &readers);
    }
    FD_SET(fileno(fp), &readers);

    rv = select(FD_SETSIZE, &readers, NULL, NULL, NULL);

    if (rv > 0) {
      if (FD_ISSET(fileno(fp), &readers)) {
        p = fgets(buf, sizeof(buf), fp);

        if (p == NULL) {
          break;
        }

        if (server.sock != -1) {
          SERR(selene_io_in_clear_bytes(server.s, p, strlen(p)));
        }
      } else if (FD_ISSET(server.listen_sock, &readers)) {
        /* TODO: multiple client support */
        if (server.sock == -1) {
          server.sock = accept(server.listen_sock, NULL, 0);

          err = selene_server_create(conf, &server.s);
          if (err != SELENE_SUCCESS) {
            fprintf(stderr,
                    "Failed to create client instance: (%d) %s [%s:%d]\n",
                    err->err, err->msg, err->file, err->line);
            exit(EXIT_FAILURE);
          }

          selene_subscribe(server.s, SELENE_EVENT_LOG_MSG, have_logline, NULL);

          SERR(selene_subscribe(server.s, SELENE_EVENT_IO_OUT_ENC, want_pull,
                                &server));

          SERR(selene_subscribe(server.s, SELENE_EVENT_IO_OUT_CLEAR,
                                have_cleartext, &server));

          SERR(selene_start(server.s));
        }
      } else if (server.sock != -1 && FD_ISSET(server.sock, &readers)) {
        read_from_sock(&server);
      }
    }
  }

  if (server.write_err != 0) {
    /* TODO: client ip */
    fprintf(stderr, "TCP write from %s:%d failed: (%d) %s\n", host, port,
            server.write_err, strerror(server.write_err));
    exit(EXIT_FAILURE);
  }

  if (server.read_err != 0) {
    /* TODO: just disconnect client, keep listening */
    fprintf(stderr, "TCP read on %s:%d failed: (%d) %s\n", host, port,
            server.read_err, strerror(server.read_err));
    exit(EXIT_FAILURE);
  }

  if (server.s) {
    selene_destroy(server.s);
    server.s = NULL;
  }

  return 0;
}

void usage() {
  fprintf(stderr, "usage: selene_server args\n");
  fprintf(stderr, "\n");
  fprintf(stderr, " -host host [%s]\n", SELENE_SERVER_DEFAULT_HOST);
  fprintf(stderr, " -port port [%d]\n", SELENE_SERVER_DEFAULT_PORT);
  fprintf(stderr, " -cert certificate_path [%s]\n",
          SELENE_SERVER_DEFAULT_CERT_PATH);
  fprintf(stderr, " -key private_key_path\n");
  fprintf(stderr, " -listen host:port\n");
  exit(EXIT_SUCCESS);
}

const char *load_cert(const char *fname) {
  FILE *fp;
  struct stat s;
  char *buf;

  fp = fopen(fname, "r");

  if (fp == NULL) {
    fprintf(stderr, "Loading '%s' failed: (%d) %s\n", fname, errno,
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  stat(fname, &s);

  buf = malloc(s.st_size + 1);

  fread(buf, s.st_size, 1, fp);

  buf[s.st_size] = '\0';

  fclose(fp);

  return buf;
}

int main(int argc, char *argv[]) {
  const char *host = SELENE_SERVER_DEFAULT_HOST;
  int port = SELENE_SERVER_DEFAULT_PORT;
  const char *cert_path = SELENE_SERVER_DEFAULT_CERT_PATH;
  const char *key_path = NULL;
  selene_conf_t *conf = NULL;
  const char *cert = NULL;
  const char *pkey = NULL;
  int rv = 0;
  int i;

  for (i = 1; i < argc; i++) {
    /* TODO: s_server compat */
    if (!strcmp("-host", argv[i]) && argc > i + 1) {
      host = argv[i + 1];
      i++;
    } else if (!strcmp("-port", argv[i]) && argc > i + 1) {
      port = atoi(argv[i + 1]);
      i++;
    } else if (!strcmp("-listen", argv[i]) && argc > i + 1) {
      char *p;
      host = argv[i + 1];
      if ((p = strstr(host, ":")) == NULL) {
        fprintf(stderr, "no port found\n");
        exit(EXIT_FAILURE);
      }
      *(p++) = '\0';
      port = atoi(p);
      i++;
    } else {
      fprintf(stderr, "Invalid args\n");
      usage();
      exit(EXIT_FAILURE);
    }
  }

  if (host == NULL) {
    fprintf(stderr, "-host must be set\n");
    exit(EXIT_FAILURE);
  }

  if (port <= 0) {
    fprintf(stderr, "-port must be set\n");
    exit(EXIT_FAILURE);
  }

  if (key_path == NULL) {
    /* assume its a pem encoded cert + key in one */
    key_path = cert_path;
  }

  SERR(selene_conf_create(&conf));

  SERR(selene_conf_use_reasonable_defaults(conf));

  cert = load_cert(cert_path);
  pkey = load_cert(key_path);
  SERR(selene_conf_cert_chain_add(conf, cert, pkey));

  rv = listen_to(conf, host, port, stdin);

  selene_conf_destroy(conf);

  if (cert) {
    free((void *)cert);
  }

  if (pkey) {
    free((void *)pkey);
  }

  return rv;
}
