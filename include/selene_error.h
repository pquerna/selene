/**
 * Copyright 2007-2010 Paul Querna.
 * Copyright 2006 Garrett Rooney.
 *
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

/* Based off of ETL's error types (which is based off of Subversion's) */

/**
 * @file selene_error.h
 */

#ifndef _selene_error_h_
#define _selene_error_h_

#include <stdint.h>
#include "selene_visibility.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Check if the @c selene_error_t returned by @a expression is equal to
 * @c SELENE_SUCCESS.  If it is, do nothing, if not, then return it.
 */
#define SELENE_ERR(expression) do {                      \
          selene_error_t *selene__xx__err = (expression);  \
          if (selene__xx__err)                           \
            return selene__xx__err;                      \
        } while (0)

/** A low level error code. */
typedef int selene_status_t;

/** Successful return value for a function that returns @c selene_error_t. */
#define SELENE_SUCCESS NULL

/** The available buffer space was exhausted. */
#define SELENE_ENOSPACE -1

/** The input was invalid. */
#define SELENE_EINVAL   -2

/** The requested functionality has not been implemented. */
#define SELENE_ENOTIMPL -3

/** The I/O operation in question failed. */
#define SELENE_EIO      -4

/** An exception object. */
typedef struct {
  /** The underlying status code. */
  selene_status_t err;

  /** A human readable error message. */
  const char *msg;

  /** The line on which the error occurred. */
  uint32_t line;

  /** The file in which the error occurred. */
  const char *file;
} selene_error_t;

/**
 * Return a new @c selene_error_t with underlying @c selene_status_t @a err
 * and message @a msg.
 */
#define selene_error_create(err, msg) selene_error_create_impl(err,    \
                                                           msg,        \
                                                           __LINE__,   \
                                                           __FILE__)

/**
 * The underlying function that implements @c selene_error_t_error_create.
 *
 * This is an implementation detail, and should not be directly called
 * by users.
 */
SELENE_API(selene_error_t *)
selene_error_create_impl(selene_status_t err, const char *msg,
                          uint32_t line,
                          const char *file);

/**
 * Return a new @c selene_error_t with underlying @c selene_status_t @a err
 * and message created @c printf style with @a fmt and varargs.
 */
#define selene_error_createf(err, fmt, ...) selene_error_createf_impl(err,         \
                                                                  __LINE__,    \
                                                                  __FILE__,    \
                                                                  fmt,         \
                                                                  __VA_ARGS__)

/**
 * The underlying function that implements @c selene_error_createf.
 *
 * This is an implementation detail, and should not be directly called
 * by users.
 */
SELENE_API(selene_error_t *)
selene_error_createf_impl(selene_status_t err,
                         uint32_t line,
                         const char *file,
                         const char *fmt,
                         ...);

/** Destroy @a err. */
SELENE_API(void)
selene_error_clear(selene_error_t *err);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
