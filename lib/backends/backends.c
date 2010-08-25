#include "sln_backends.h"

selene_error_t*
sln_backend_create(selene_t *s)
{
#if defined(WANT_OPENSSL_THREADED)
  return sln_openssl_threaded_create(s);
#else
  return selene_error_createf(SELENE_EINVAL, "no backend specified");
#endif
} 

void
sln_backend_destroy(selene_t *s)
{
  if (s && s->backend) {
#if defined(WANT_OPENSSL_THREADED)
    sln_openssl_threaded_destroy(s);
#else
    return selene_error_createf(SELENE_EINVAL, "no backend specified");
#endif
  }
}

