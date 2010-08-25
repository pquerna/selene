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

#ifndef _sln_log_h_
#define _sln_log_h_

#include <stdarg.h>

typedef enum
{
  SLN_LOG__UNUSED0,
  SLN_LOG_NOTHING,
  SLN_LOG_CRITICAL,
  SLN_LOG_ERRORS,
  SLN_LOG_WARNINGS,
  SLN_LOG_INFO,
  SLN_LOG_DEBUG,
  SLN_LOG_TRACE,
  SLN_LOG_EVERYTHING,
  SLN_LOG__MAX
} sln_log_level_e;

void sln_log_level_set(selene_t *s, sln_log_level_e level);
sln_log_level_e sln_log_level_get(selene_t *s);

void sln_log(selene_t *s, sln_log_level_e level, const char *str);
void sln_log_fmtv(selene_t *s, sln_log_level_e level, const char* fmt, va_list ap);
#if !defined(SWIG) && !defined(_MSC_VER)
#define SLN_FMT_FUNC(x,y) __attribute__((format(printf,x,y)))
#else
#define SLN_FMT_FUNC(x,y)
#endif

void sln_log_fmt(selene_t *s, sln_log_level_e level, const char* fmt, ...) SLN_FMT_FUNC(3,4);
void sln_log_criticalf(selene_t *s, const char *fmt, ...) SLN_FMT_FUNC(2,3);
void sln_log_errorf(selene_t *s, const char *fmt, ...) SLN_FMT_FUNC(2,3);
void sln_log_warningf(selene_t *s, const char *fmt, ...) SLN_FMT_FUNC(2,3);
void sln_log_infof(selene_t *s, const char *fmt, ...) SLN_FMT_FUNC(2,3);
void sln_log_debugf(selene_t *s, const char *fmt, ...) SLN_FMT_FUNC(2,3);
void sln_log_tracef(selene_t *s, const char *fmt, ...) SLN_FMT_FUNC(2,3);

#ifndef slnCrit
#define slnCrit sln_log_criticalf
#endif

#ifndef slnErr
#define slnErr sln_log_errorf
#endif

#ifndef slnWarn
#define slnWarn sln_log_warningf
#endif

#ifndef slnInfo
#define slnInfo sln_log_infof
#endif

#ifndef slnDbg
#define slnDbg sln_log_debugf
#endif

#ifndef slnTrace
#define slnTrace sln_log_tracef
#endif

#endif
