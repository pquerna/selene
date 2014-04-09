#
# Licensed to Selene developers ('Selene') under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# Selene licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

EnsureSConsVersion(1, 1, 0)

SetOption('num_jobs', 4)

import os, sys, fnmatch
from site_scons import ac
from os.path import join as pjoin

def _get_files(env, source, globs, reldir=os.curdir):
  results = []
  if not os.path.isdir(source):
    return results
  for entry in os.listdir(source):
    fullpath = os.path.join(source, entry)
    if os.path.islink(fullpath):
      continue
    if os.path.isfile(fullpath):
      if any((fnmatch.fnmatchcase(fullpath, i) for i in globs)):
        results.append(fullpath)
    elif os.path.isdir(fullpath):
      newrel = os.path.join(reldir, entry)
      results.extend(_get_files(env, fullpath, globs, newrel))
  return results


opts = Variables('build.py')

opts.Add(PathVariable('with_openssl',
                      'Prefix to OpenSSL installation', None))

available_profiles = ['debug', 'gcov', 'release']
available_build_types = ['static', 'shared']
opts.Add(EnumVariable('profile', 'build profile', 'debug', available_profiles, {}, True))
opts.Add(EnumVariable('build_type', 'build profile', 'static', available_build_types, {}, True))

env = Environment(options=opts,
                  ENV = os.environ.copy(),
                  tools=['default'])

env.SConscript('site_scons/ca_builder.py', exports="env")

prefer_clang = True

if 'coverage' in COMMAND_LINE_TARGETS:
  prefer_clang = False
  env['profile'] = 'gcov'
  env['build_type'] = 'static'

conf = Configure(env, custom_tests = {'CheckUname': ac.CheckUname})

conf.env['PYTHON'] = env.WhereIs('python')
if not conf.env['PYTHON']:
  conf.env['PYTHON'] = sys.executable

if not conf.env.get('CLANG'):
  conf.env['CLANG'] = env.WhereIs('clang')

if not conf.env.get('CLANGXX'):
  conf.env['CLANGXX'] = env.WhereIs('clang++')

if os.environ.has_key('CC'):
  conf.env['CC'] = os.environ['CC']
elif conf.env['CLANG'] and prefer_clang:
  conf.env['CC'] = conf.env['CLANG']

if os.environ.has_key('CXX'):
  conf.env['CXX'] = os.environ['CXX']
elif conf.env['CLANGXX'] and prefer_clang:
  conf.env['CXX'] = conf.env['CLANGXX']

(st, platform) = conf.CheckUname("-sm")

conf.env['SELENE_PLATFORM'] = platform[:platform.find(' ')].upper()
conf.env['SELENE_ARCH'] = platform[platform.find(' ')+1:].replace(" ", "_")

if conf.env['SELENE_PLATFORM'] == "DARWIN" and conf.env.get('CLANG'):
  # try to use a specific gcc version, because /usr/bin/gcc is a symlink to
  # clang in 10.7, but clang doesn't yet support profiling :(
  gcc_vers = [conf.env.WhereIs('gcc%s' % x) for x in ['-4.6', '-4.5', '-4.4', '-4.3', '-4.2', '-4.1', '']]
  conf.env['PROFILE_CC'] = next(s for s in gcc_vers if s)
  print 'Checking for compiler that supports profiling ... %s' % conf.env['PROFILE_CC']

conf.env['WANT_OPENSSL'] = True

if not conf.CheckCC():
  print 'Unable to find a functioning compiler, tried %s' % (conf.env.get('CC'))
  Exit(-1)

if conf.env['WANT_OPENSSL']:
  if conf.env.get('with_openssl'):
    conf.env.AppendUnique(LIBPATH=["${with_openssl}/lib"])
    conf.env.AppendUnique(CPPPATH=["${with_openssl}/include"])
  conf.env['HAVE_OPENSSL'] = conf.CheckLibWithHeader('libssl', 'openssl/ssl.h', 'C', 'SSL_library_init();', True)
  if not conf.env['HAVE_OPENSSL']:
    print 'Unable to use OpenSSL development enviroment: with_openssl=%s' %  conf.env.get('with_openssl')
    Exit(-1)
  conf.env['HAVE_CRYPTO'] = conf.CheckLibWithHeader('libcrypto', 'openssl/err.h', 'C', 'ERR_load_crypto_strings();', True)
  if not conf.env['HAVE_CRYPTO']:
    print 'Unable to use OpenSSL development enviroment (missing libcrypto?): with_openssl=%s' %  conf.env.get('with_openssl')
    Exit(-1)

conf.env['HAVE_OSX_COMMONCRYPTO'] = conf.CheckLibWithHeader('libSystem', 'CommonCrypto/CommonDigest.h', 'C', 'CC_SHA1_CTX ctx; CC_SHA1_Init(&ctx);', True)
if conf.env['HAVE_OSX_COMMONCRYPTO']:
  conf.env.AppendUnique(CPPDEFINES=['SLN_HAVE_OSX_COMMONCRYPTO'])

# TODO: consider '-fmudflap', '-fstack-check'
for flag in ['-pedantic', '-std=gnu89', '-Wno-variadic-macros', '-Wno-deprecated-declarations']:
  conf.env.AppendUnique(CCFLAGS=flag)
  if not conf.CheckCC():
    print 'Checking for compiler support of %s ... no' % flag
    conf.env['CCFLAGS'] = filter(lambda x: x != flag, conf.env['CCFLAGS'])
  else:
    print 'Checking for compiler support of %s ... yes' % flag

env = conf.Finish()

env.AppendUnique(CPPPATH=['#/include'])

options = {
  'PLATFORM': {
    'DARWIN': {
      'CPPDEFINES': ['DARWIN'],
    },
    'LINUX': {
      'CPPDEFINES': ['LINUX', '_XOPEN_SOURCE', '_BSD_SOURCE'],
    },
    'FREEBSD': {
      'CPPDEFINES': ['FREEBSD'],
    },
  },
  'PROFILE': {
    'DEBUG': {
      'CCFLAGS': ['-Wall', '-O0', '-ggdb'],
      'CPPDEFINES': ['DEBUG'],
    },
    'GCOV': {
      'CC': env.get('PROFILE_CC', env['CC']),
      'CCFLAGS': ['-Wall', '-O0', '-ggdb', '-fPIC', '-fprofile-arcs', '-ftest-coverage'],
      'CPPDEFINES': ['DEBUG'],
      'LIBS': 'gcov'
    },
    'RELEASE': {
      'CCFLAGS': ['-Wall', '-O2'],
      'CPPDEFINES': ['NODEBUG'],
    },
  },
}

selected_variant = '%s-%s' % (env['profile'].lower(), env['build_type'].lower())
print "Selected %s variant build..." % (selected_variant)

variants = []
for platform in [env['SELENE_PLATFORM']]:
  bt = [env['build_type'].upper()]
  for profile in available_profiles:
    for build in available_build_types:
      variants.append({'PLATFORM': platform.upper(), 'PROFILE': profile.upper(), 'BUILD': build.upper()})

append_types = ['CCFLAGS', 'CFLAGS', 'CPPDEFINES', 'LIBS']
replace_types = ['CC']
cov_targets = []

all_targets = {}
all_test_targets = {}

for vari in variants:
  targets = []
  test_targets = []
  coverage_test_targets = []
  platform = vari['PLATFORM']
  profile =  vari['PROFILE']
  build = vari['BUILD']
  variant = '%s-%s' % (profile.lower(), build.lower())
  vdir = pjoin('build', variant)
  venv = env.Clone()
  venv['SELENE_LIB_TYPE'] = build

  for k in sorted(options.keys()):
    ty = vari.get(k)
    if options[k].has_key(ty):
      for key,value in options[k][ty].iteritems():
        if key in append_types:
          p = {key: value}
          venv.AppendUnique(**p)
        elif key in replace_types:
          venv[key] = value
        else:
          print('Fix the SConsscript, its missing support for %s' % (key))
          Exit(1)

  lib = venv.SConscript('lib/SConscript', variant_dir=pjoin(vdir, 'lib'), duplicate=0, exports='venv')
  targets.append(lib)
  venv['libselene'] = lib[0]
  venv['VDIR'] = vdir
  tests = venv.SConscript('tests/SConscript', variant_dir=pjoin(vdir, 'tests'), duplicate=0, exports='venv')
  for t in tests[0]:
    run = venv.Command(str(t) + ".testrun", t,
      [
      ""+str(t)
      ])
    venv.AlwaysBuild(run)
    test_targets.append(run)
    if ty == "GCOV":
      cleancov = venv.Command(venv.File('$VDIR/.covclean'), coverage_test_targets,
                ['find $VDIR -name \*.gcda -delete'])
      venv.AlwaysBuild(cleancov)
      venv.Depends(run, cleancov)
      coverage_test_targets.append(run)

  if ty == "GCOV" and variant == selected_variant:
    cov = venv.Command(venv.File('%s/coverage.txt' % (vdir)), coverage_test_targets,
              # TODO: in an ideal world, we could use --object-directory=$VDIR
              ['$PYTHON ./tests/gcovr -r . --object-directory=. -e extern -e build -e test -o $VDIR/coverage.txt',
               'cat $VDIR/coverage.txt'])
    venv.AlwaysBuild(cov)
    cov_targets.append(cov)
  tools = venv.SConscript('tools/SConscript', variant_dir=pjoin(vdir, 'tools'), duplicate=0, exports='venv')
  targets.append(tools)

  all_targets[variant] = targets
  all_test_targets[variant] = test_targets

denv = env.Clone()
denv['DOXYGEN'] = 'doxygen'
doxy = denv.Command(env.Dir('#/api-docs'), env.Glob("include/**"),
                   ['rm -rf api-docs',
                    '$DOXYGEN'])
denv.AlwaysBuild(doxy)


fenv = env.Clone()
all_source_files = _get_files(fenv, 'lib', ['*.c', '*.h']) + \
                   _get_files(fenv, 'include', ['*.c', '*.h']) + \
                   _get_files(fenv, 'test', ['*.c', '*.h'])
fenv['CLANG_FORMAT'] = 'clang-format'
fenv['CLANG_FORMAT_OPTIONS'] = '-style=Google -i'
formatit = fenv.Command('.clang-format-all-source', all_source_files,
                    '$CLANG_FORMAT $CLANG_FORMAT_OPTIONS $SOURCES')
fenv.AlwaysBuild(formatit)

env.Alias('docs', doxy)
env.Alias('test', all_test_targets[selected_variant])
env.Alias('coverage', cov_targets)
env.Alias('format', formatit)

if env.GetOption('clean'):
  env.Clean(all_targets.values()[0], _get_files(env, 'build', ['*.gcda', '*.gcno']))
  env.Default([all_targets.values(),
               all_test_targets.values(),
               cov_targets])
else:
  env.Default([all_targets[selected_variant]])
