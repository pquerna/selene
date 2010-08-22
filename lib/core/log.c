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

#include "sln_types.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

void sln_log_level_set(selene_t *s, sln_log_level_e level)
{
  s->log_level = level;
}

sln_log_level_e sln_log_level_get(selene_t *s)
{
  return s->log_level;
}

#define SLN_LOG_TO_STDERR 0
/* Logs a completely formated string into the current log file.
 * Line must include newline, and is written regardless of the log level.
 */
static void sln_log_publish(selene_t *s, sln_log_level_e level,
                            const char *str, size_t len)
{
  s->log_msg = str;
  s->log_msg_len = len;
  s->log_msg_level = level;

  selene_publish(s, SELENE_EVENT_LOG_MSG);

#if SLN_LOG_TO_STDERR
  fwrite(str, 1, strlen(str), stderr);
  fflush(stderr);
#endif

  /* These are allocated off the stack, we don't want soemone to grab them later out of place. */
  s->log_msg = NULL;
  s->log_msg_len = 0;
  s->log_msg_level = SLN_LOG_NOTHING;
}

void
selene_log_msg_get(selene_t *s, const char **log_msg,
                   size_t *log_msg_len)
{
  *log_msg = s->log_msg;
  *log_msg_len = s->log_msg_len;
}

/* Prepends date, level, and appends newline*/
void sln_log(selene_t *s, sln_log_level_e level, const char *str)
{
  if (sln_log_level_get(s) < level) {
    return;
  }
  else {
    time_t t;
    char buf[1100] = {0};
    size_t slen = 0;
    size_t blen = 0;
    size_t availlen;
    struct tm tm;
    struct tm *ptm;
    const char *llstr = NULL;

    slen = strlen(str);
    t = time(NULL);

#ifdef _WIN32
    /* modern version of msvc use a thread-local buffer for gmtime_r */
    ptm = gmtime(&t);
    memcpy(&tm, ptm, sizeof(struct tm));
    ptm = &tm;
    {
      char *p = asctime(ptm);
      memcpy(&buf[0], p, 24);
    }
#else
    ptm = gmtime_r(&t, &tm);
    /* TODO: use a different time format ?*/
    asctime_r(ptm, &buf[0]);
#endif
    blen += 24;
    switch (level) {
      case SLN_LOG_CRITICAL:
        llstr = " CRT: ";
        break;
      case SLN_LOG_ERRORS:
        llstr = " ERR: ";
        break;
      case SLN_LOG_WARNINGS:
        llstr = " WRN: ";
        break;
      case SLN_LOG_INFO:
        llstr = " INF: ";
        break;
      case SLN_LOG_DEBUG:
        llstr = " DBG: ";
        break;
      case SLN_LOG_TRACE:
        llstr = " TRC: ";
        break;
      default:
        llstr = " UNK: ";
        break;
    }

    memcpy(&buf[0]+blen, llstr, 6);
    blen += 6;

    availlen = sizeof(buf) - blen - 2;

    if (slen > availlen) {
      slen = availlen;
    }

    memcpy(&buf[0]+blen, str, slen);
    blen += slen;

    memcpy(&buf[0]+blen, "\n\0", 2);
    blen += 2;
    sln_log_publish(s, level, &buf[0], blen);
  }
}

void sln_log_fmtv(selene_t *s, sln_log_level_e level, const char *fmt, va_list ap)
{
  if (sln_log_level_get(s) >= level) {
    char buf[1024];
    int rv = vsnprintf(&buf[0], sizeof(buf), fmt, ap);
    if (rv >= 0) {
      /* PQ:TODO: This is not as efficient as it could be, we could build
       * the log line inline here with a little code refactoring, rather than 
       * an inline snprintf/calling out to the string based logger.
       */
      sln_log(s, level, buf);
    }
  }
}

void sln_log_fmt(selene_t *s, sln_log_level_e level, const char* fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  sln_log_fmtv(s, level, fmt, ap);
  va_end(ap);
}

void seln_log_criticalf(selene_t *s, const char *fmt, ...)
{
  va_list ap;
  
  va_start(ap, fmt);
  sln_log_fmtv(s, SLN_LOG_CRITICAL, fmt, ap);
  va_end(ap);
}

void sln_log_errorf(selene_t *s, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  sln_log_fmtv(s, SLN_LOG_ERRORS, fmt, ap);
  va_end(ap);
}

void sln_log_warningf(selene_t *s, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  sln_log_fmtv(s, SLN_LOG_WARNINGS, fmt, ap);
  va_end(ap);
}

void sln_log_infof(selene_t *s, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  sln_log_fmtv(s, SLN_LOG_INFO, fmt, ap);
  va_end(ap);
}

void sln_log_debugf(selene_t *s, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  sln_log_fmtv(s, SLN_LOG_DEBUG, fmt, ap);
  va_end(ap);
}

void sln_log_tracef(selene_t *s, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  sln_log_fmtv(s, SLN_LOG_TRACE, fmt, ap);
  va_end(ap);
}
