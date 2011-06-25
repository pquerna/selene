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
#include "sln_types.h"
#include "sln_assert.h"

#define SLN_GUARD_EVENT_SIZE(action, e) \
  do { \
    if (e >= SELENE_EVENT__MAX) { \
      return selene_error_createf(SELENE_EINVAL, \
                                "attempt to %s on %d which is greater than all known events", \
                                action, event); \
    } \
    if (e <= SELENE_EVENT__UNUSED0) { \
      return selene_error_createf(SELENE_EINVAL, \
                                "attempt to %s on %d which is less than all known events", \
                                action, event); \
    } \
  } while (0)


#define SLN_EVENTS_INSERT_TAIL(b, e) \
  do { \
    sln_eventcb_t *sln__e = (e); \
    SLN_RING_INSERT_TAIL(&(b)->list, sln__e, sln_eventcb_t, link); \
  } while (0)

selene_error_t*
sln_events_create(selene_t *s)
{
  int i;
  s->events = sln_calloc(s, sizeof(sln_events_t) * SELENE_EVENT__MAX);
  for (i = 0; i < SELENE_EVENT__MAX; i++) {
    sln_events_t *events = &(s->events[i]);
    SLN_RING_INIT(&events->list, sln_eventcb_t, link);
    events->event = i;
  }
  return SELENE_SUCCESS;
}

void
sln_events_destroy(selene_t *s)
{
  int i;
  for (i = 0; i < SELENE_EVENT__MAX; i++) {
    sln_events_t *events = &(s->events[i]);
    while (!SLN_RING_EMPTY(&(events)->list, sln_eventcb_t, link)) {
      sln_eventcb_t *e = SLN_RING_FIRST(&(events)->list);
      SLN_RING_REMOVE(e, link);
      sln_free(s, e);
    }
  }
  sln_free(s, s->events);
}

selene_error_t*
selene_handler_set(selene_t *s, selene_event_e event,
                   selene_event_cb cb, void *baton)
{
  sln_events_t *events;

  SLN_ASSERT_CONTEXT(s);
  SLN_ASSERT_ENUM(SELENE_EVENT, event);

  SLN_GUARD_EVENT_SIZE("set", event);

  events = &(s->events[event]);

  events->handler = cb;
  events->handler_baton = baton;

  return SELENE_SUCCESS;
}

selene_error_t*
selene_subscribe(selene_t *s, selene_event_e event,
                 selene_event_cb cb, void *baton)
{
  sln_eventcb_t *b;
  sln_events_t *events;

  SLN_ASSERT_CONTEXT(s);
  SLN_ASSERT_ENUM(SELENE_EVENT, event);

  SLN_GUARD_EVENT_SIZE("subscribe", event);

  events = &(s->events[event]);

  b = sln_calloc(s, sizeof(sln_eventcb_t));

  b->cb = cb;
  b->baton = baton;

  SLN_EVENTS_INSERT_TAIL(events, b);

  return SELENE_SUCCESS;
}

selene_error_t*
selene_unsubscribe(selene_t *s, selene_event_e event,
                 selene_event_cb cb, void *baton)
{
  sln_eventcb_t *b;
  sln_events_t *events;

  SLN_ASSERT_CONTEXT(s);
  SLN_ASSERT_ENUM(SELENE_EVENT, event);

  SLN_GUARD_EVENT_SIZE("unsubscribe", event);

  events = &(s->events[event]);
  SLN_RING_FOREACH(b, &(events)->list, sln_eventcb_t, link)
  {
    if (b->cb == cb && b->baton == baton) {
      SLN_RING_REMOVE(b, link);
      sln_free(s, b);
      return SELENE_SUCCESS;
    }
  }

  return SELENE_SUCCESS;
}

selene_error_t*
selene_publish(selene_t *s, selene_event_e event)
{
  sln_eventcb_t *b;
  sln_events_t *events;

  SLN_ASSERT_CONTEXT(s);
  SLN_ASSERT_ENUM(SELENE_EVENT, event);

  SLN_GUARD_EVENT_SIZE("publish", event);

  events = &(s->events[event]);
  if (events->handler != NULL) {
    events->handler(s, event, events->handler_baton);
  }

  SLN_RING_FOREACH(b, &(events)->list, sln_eventcb_t, link)
  {
    SELENE_ERR(b->cb(s, event, b->baton));
  }

  return SELENE_SUCCESS;
}


