# config
enable_openssl_threaded=1
enable_native=1
# config end


uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

ifeq ($(uname_S),Darwin)
	CC = clang
	CPPDEFINES += DARWIN
endif

ifeq ($(uname_S),Linux)
	CPPDEFINES += LINUX _XOPEN_SOURCE
endif

ifeq ($(uname_S),FreeBSD)
	CPPDEFINES += FREEBSD
endif

CFLAGS +=

ifdef enable_native
	WANT_OPENSSL = 1
	OPENSSL_CFLAGS += -DWANT_NATIVE
endif

ifdef enable_openssl_threaded
	WANT_OPENSSL = 1
	OPENSSL_CPPFLAGS += -DWANT_OPENSSL_THREADED 
	OPENSSL_CPPFLAGS += -DWANT_PTHREADS
	OPENSSL_LINKFLAGS += -lpthread
endif

ifdef WANT_OPENSSL
	HAVE_OPENSSL = 1
	HAVE_CRYPTO = 1
	ifdef OPENSSL_DIR
		OPENSSL_LINKFLAGS += -L$(OPENSSL_DIR)/lib
		OPENSSL_CPPFLAGS += -I$(OPENSSL_DIR)/include
	endif
	OPENSSL_LINKFLAGS += -lssl -lcrypto
endif

# Default profile is debug 'make PROFILE=release' for a release.
PROFILE ?= debug

debug_CFLAGS = -Wall -O0 -ggdb
debug_CPPDEFINES = -DDEBUG
debug_builddir = build/debug

gcov_CFLAGS = -Wall -O0 -ggdb -fPIC -fprofile-arcs -ftest-coverage
gcov_CPPFLAGS = -DDEBUG
gcov_LINKFLAGS = -lgcov
gcov_builddir = build/gcov

release_CFLAGS = -Wall -O2
release_CPPDEFINES = -DNODEBUG
release_builddir = build/release

ifeq (gcov,$(PROFILE))
	CC = gcc
endif

CFLAGS    += $($(PROFILE)_CFLAGS)
CPPFLAGS  += $($(PROFILE)_CPPFLAGS)
LINKFLAGS += $($(PROFILE)_LINKFLAGS)
builddir   = $($(PROFILE)_builddir)


CLIENT_CPPFLAGS = -Iinclude $(OPENSSL_CPPFLAGS)
CLIENT_CFLAGS = $(CFLAGS) $(OPENSSL_CFLAGS)
CLIENT_LINKFLAGS = $(LINKFLAGS) $(OPENSSL_LINKFLAGS)

TEST_CPPFLAGS = -Iextern/cmockery/src/google -Iinclude -Iinclude/private \
								$(OPENSSL_CPPFLAGS) -DUNIT_TESTING=1
TEST_CFLAGS = $(CFLAGS) $(OPENSSL_CFLAGS)
TEST_LINKFLAGS = $(LINKFLAGS) $(OPENSSL_LINKFLAGS)

SELENE_CPPFLAGS = $(CPPFLAGS) $(OPENSSL_CPPFLAGS)
SELENE_CFLAGS = $(CFLAGS) $(OPENSSL_CFLAGS)
SELENE_LINKFLAGS = $(LINKFLAGS) $(OPENSSL_LINKFLAGS)

CPPPATH += include include/private
CPPFLAGS = $(addprefix -D,$(CPPDEFINES)) $(addprefix -I,$(CPPPATH))
ALL_CFLAGS = $(CPPFLAGS) $(CFLAGS)
LINK_FLAGS = $(addprefix -L,$(LIBPATH)) $(addprefix -l,$(LIBS))




# The files we're going to build:
lib = $(builddir)/libselene.a

objects = $(addprefix $(builddir)/lib/, \
	backends/backends.o \
	backends/openssl_threaded/init.o \
	backends/openssl_threaded/io.o \
	backends/openssl_threaded/util.o \
	core/conf.o \
	core/error.o \
	core/event.o \
	core/init.o \
	core/log.o \
	io/brigades.o \
	io/buckets.o \
	io/io.o)

object_dirs = $(addprefix $(builddir)/, \
	lib/io lib/backends lib/core lib/backends/openssl_threaded extern)

cmockery_object = $(builddir)/extern/cmockery.o
selene_client = $(builddir)/selene_client


# Rules

.PHONY: all
all:
all: $(lib) tests $(selene_client)


.phony: clean
clean:
	-rm -f $(objects) $(builddir)/test $(cmockery_object)

.PHONY: distclean
distclean:
	-rm -rf build


# Make sure all the directories exist
$(objects) : $(object_dirs)
$(cmockery_object) : $(object_dirs)

$(object_dirs) :
	mkdir -p $@


$(lib): $(objects)
	$(AR) r $(lib) $?
	ranlib $(lib)


# Build objects
$(builddir)/%.o: %.c 
	$(CC) -c $(SELENE_CFLAGS) $(SELENE_CPPFLAGS) $< -o $@


# header dependencies 
# Just maintain this list manually - it's not that dynamic
# made with the help of: grep 'include "' lib/**/*.c include/**/*.h
lib/backends/backends.c: include/private/sln_backends.h
lib/backends/openssl_threaded/init.c: lib/backends/openssl_threaded/openssl_threaded.h
lib/backends/openssl_threaded/init.c: include/private/sln_brigades.h
lib/backends/openssl_threaded/io.c: lib/backends/openssl_threaded/openssl_threaded.h
lib/backends/openssl_threaded/io.c: include/private/sln_brigades.h
lib/backends/openssl_threaded/util.c: lib/backends/openssl_threaded/openssl_threaded.h
lib/core/conf.c: include/selene.h
lib/core/conf.c: include/private/sln_types.h
lib/core/error.c: include/selene_error.h
lib/core/event.c: include/selene.h
lib/core/event.c: include/private/sln_types.h
lib/core/event.c: include/private/sln_assert.h
lib/core/init.c: include/selene.h
lib/core/init.c: include/private/sln_types.h
lib/core/init.c: include/private/sln_brigades.h
lib/core/init.c: include/private/sln_events.h
lib/core/init.c: include/private/sln_backends.h
lib/core/init.c: include/private/sln_assert.h
lib/core/log.c: include/private/sln_types.h
lib/io/brigades.c: include/private/sln_brigades.h
lib/io/brigades.c: include/private/sln_types.h
lib/io/brigades.c: include/private/sln_assert.h
lib/io/buckets.c: include/private/sln_brigades.h
lib/io/buckets.c: include/private/sln_buckets.h
lib/io/buckets.c: include/private/sln_types.h
lib/io/io.c: include/selene.h
lib/io/io.c: include/private/sln_types.h
lib/io/io.c: include/private/sln_brigades.h
include/private/sln_backends.h: include/selene.h
include/private/sln_backends.h: include/private/sln_types.h
include/private/sln_backends.h: include/private/sln_buckets.h
include/private/sln_brigades.h: include/selene.h
include/private/sln_brigades.h: include/private/sln_types.h
include/private/sln_brigades.h: include/private/sln_buckets.h
include/private/sln_buckets.h: include/selene.h
include/private/sln_buckets.h: include/private/sln_types.h
include/private/sln_events.h: include/selene.h
include/private/sln_events.h: include/private/sln_types.h
include/private/sln_types.h: include/selene.h
include/private/sln_types.h: include/private/sln_log.h
include/private/sln_types.h: include/private/sln_ring.h
include/selene.h: include/selene_visibility.h
include/selene.h: include/selene_version.h
include/selene.h: include/selene_error.h
include/selene_error.h: include/selene_visibility.h


$(selene_client): tools/selene_client.c $(lib)
	$(CC) -o $@ $^ $(CLIENT_CPPFLAGS) $(CLIENT_CFLAGS) $(CLIENT_LINKFLAGS)


.PHONY: tests
tests: $(builddir)/test

$(cmockery_object): extern/cmockery/src/cmockery.c
	$(CC) -c $< -o $@ $(TEST_CPPFLAGS) $(TEST_CFLAGS)

$(builddir)/test: tests/test_init.c $(lib) $(cmockery_object) tests/sln_tests.h
	$(CC) -o $@ $(TEST_CPPFLAGS) $(TEST_CFLAGS) $(TEST_LINKFLAGS) \
		tests/test_init.c $(lib) $(cmockery_object) 




