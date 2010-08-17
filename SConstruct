#
# Licensed to Paul Querna under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# Paul Querna licenses this file to You under the Apache License, Version 2.0
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

import os
from site_scons import ac
from os.path import join as pjoin

opts = Variables('build.py')

opts.Add(PathVariable('with_openssl',
                      'Prefix to OpenSSL installation', None))

opts.Add('enable_openssl_threaded', default=True, help='Enable Threaded OpenSSL backend')

env = Environment(options=opts,
                  ENV = os.environ.copy(),
                  tools=['default'])

conf = Configure(env, custom_tests = {'CheckUname': ac.CheckUname})

(st, platform) = conf.CheckUname("-sm")

conf.env['SELENE_PLATFORM'] = platform[:platform.find(' ')].upper()
conf.env['SELENE_ARCH'] = platform[platform.find(' ')+1:].replace(" ", "_")

if conf.env['enable_openssl_threaded']:
  conf.env['WANT_OPENSSL'] = True
  conf.env.AppendUnique(CPPDEFINES=['WANT_OPENSSL_THREADED'])

if conf.env['WANT_OPENSSL']:
  if conf.env.get('with_openssl'):
    conf.env.AppendUnique(LIBPATH=["${with_openssl}/lib"])
    conf.env.AppendUnique(CPPPATH=["${with_openssl}/include"])
  conf.env['HAVE_OPENSSL'] = conf.CheckLibWithHeader('libssl', 'openssl/ssl.h', 'C', 'SSL_library_init();', True)
  if not conf.env['HAVE_OPENSSL']:
    print 'Unable to use OpenSSL development enviroment: with_openssl=%s' %  conf.env.get('with_openssl')
    Exit(-1)

env = conf.Finish()

options = {
  'PLATFORM': {
    'DARWIN': {
      'CC': '/usr/bin/clang',
      'CPPDEFINES': ['DARWIN'],
    },
    'LINUX': {
      'CPPDEFINES': ['LINUX'],
    },
  },
  'PROFILE': {
    'DEBUG': {
      'CCFLAGS': ['-Wall', '-O0', '-ggdb'],
      'CPPDEFINES': ['DEBUG'],
    },
    'GCOV': {
      'CC': 'gcc',
      'CCFLAGS': ['-Wall', '-O0', '-ggdb', '-fprofile-arcs', '-ftest-coverage'],
      'CPPDEFINES': ['DEBUG'],
    },
    'RELEASE': {
      'CCFLAGS': ['-Wall', '-Os'],
      'CPPDEFINES': ['NODEBUG'],
    },
  },
}

# TODO: autodetect/let users pick these:
variants = [
  {'PLATFORM': conf.env['SELENE_PLATFORM'], 'PROFILE': 'DEBUG', 'BUILD': 'STATIC'},
#  {'PLATFORM': 'DARWIN', 'PROFILE': 'DEBUG', 'BUILD': 'SHARED'}
]

append_types = ['CCFLAGS', 'CFLAGS', 'CPPDEFINES']
replace_types = ['CC']
targets = []
test_targets = []

# defaults for all platforms
env.AppendUnique(CPPPATH=['#/include'])

for vari in variants:
  platform = vari['PLATFORM']
  profile =  vari['PROFILE']
  build = vari['BUILD']
  variant = '%s-%s-%s' % (platform.lower(), profile.lower(), build.lower())
  vdir = pjoin('build', variant)
  venv = env.Clone()
  venv['SELEN_LIB_TYPE'] = build

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

  tests = venv.SConscript('tests/SConscript', variant_dir=pjoin(vdir, 'tests'), duplicate=0, exports='venv')
  for t in tests[0]:
    run = venv.Command(str(t) + ".testrun", t,
      [
      ""+str(t)
      ])
    venv.AlwaysBuild(run)
    test_targets.append(run)

  tools = venv.SConscript('tools/SConscript', variant_dir=pjoin(vdir, 'tools'), duplicate=0, exports='venv')
  targets.append(tools)

env.Alias('test', test_targets)
if not env.GetOption('clean'):
  env.Default(targets)
else:
  env.Default([targets, 'test'])
