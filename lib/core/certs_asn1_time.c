/*
 * Conversion from ASN1 Time to a time_exp_t is dervived from
 *   <httpd/modules/ssl/ssl_engine_vars.c>  ssl_var_lookup_ssl_cert_remain
 * (Portable) Conversion from a time_exp_t to a int64_t is
 */

/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
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

/*                      _             _
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 *  ssl_engine_vars.c
 *  Variable Lookup Facility
 */
                             /* ``Those of you who think they
                                  know everything are very annoying
                                  to those of us who do.''
                                                  -- Unknown       */

#include <stdint.h>
#include "sln_certs.h"
#include <time.h>
#include <openssl/ssl.h>

#define USEC_PER_SEC   INT64_C(1000000)

/**
 * a structure similar to ANSI struct tm with the following differences:
 *  - tm_usec isn't an ANSI field
 *  - tm_gmtoff isn't an ANSI field (it's a bsdism)
 */
typedef struct time_exp_t {
  /** microseconds past tm_sec */
  int32_t tm_usec;
  /** (0-61) seconds past tm_min */
  int32_t tm_sec;
  /** (0-59) minutes past tm_hour */
  int32_t tm_min;
  /** (0-23) hours past midnight */
  int32_t tm_hour;
  /** (1-31) day of the month */
  int32_t tm_mday;
  /** (0-11) month of the year */
  int32_t tm_mon;
  /** year since 1900 */
  int32_t tm_year;
  /** (0-6) days since sunday */
  int32_t tm_wday;
  /** (0-365) days since jan 1 */
  int32_t tm_yday;
  /** daylight saving time */
  int32_t tm_isdst;
  /** seconds east of UTC */
  int32_t tm_gmtoff;
} time_exp_t;

static void 
time_exp_gmt_get(int64_t *t, time_exp_t *xt)
{
  int64_t year = xt->tm_year;
  int64_t days;
  static const int dayoffset[12] = {306, 337, 0, 31, 61, 92, 122, 153, 184, 214, 245, 275};

  /* shift new year to 1st March in order to make leap year calc easy */
  if (xt->tm_mon < 2) {
    year--;
  }

  /* Find number of days since 1st March 1900 (in the Gregorian calendar). */
  days = year * 365 + year / 4 - year / 100 + (year / 100 + 3) / 4;
  days += dayoffset[xt->tm_mon] + xt->tm_mday - 1;
  days -= 25508;              /* 1 jan 1970 is 25508 days since 1 mar 1900 */
  days = ((days * 24 + xt->tm_hour) * 60 + xt->tm_min) * 60 + xt->tm_sec;

  if (days < 0) {
    *t = 0;
    return;
  }

  *t = days + xt->tm_usec;
}

#define DIGIT2NUM(x) (((x)[0] - '0') * 10 + (x)[1] - '0')

int64_t
sln_asn1_time_to_timestamp(ASN1_UTCTIME *tm)
{
  int64_t rv = 0;
  /* Converts a ASN1_UTCTIME to an int64_t of seconds since 1970.  Returns 0 on failure. */
  time_exp_t exp = {0};

  /* Fail if the time isn't a valid ASN.1 UTCTIME; RFC3280 mandates
  * that the seconds digits are present even though ASN.1
  * doesn't. */
  if (tm->length < 11 || !ASN1_UTCTIME_check(tm)) {
    return 0;
  }

  exp.tm_year = DIGIT2NUM(tm->data);
  exp.tm_mon = DIGIT2NUM(tm->data + 2) - 1;
  exp.tm_mday = DIGIT2NUM(tm->data + 4) + 1;
  exp.tm_hour = DIGIT2NUM(tm->data + 6);
  exp.tm_min = DIGIT2NUM(tm->data + 8);
  exp.tm_sec = DIGIT2NUM(tm->data + 10);

  if (exp.tm_year <= 50) {
    exp.tm_year += 100;
  }

  time_exp_gmt_get(&rv, &exp);

  return rv;
}
