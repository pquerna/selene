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
from os.path import join as pjoin

opts = Variables('build.py')

env = Environment(options=opts,
                  ENV = os.environ.copy(),
                  tools=['default'])

options = {
  'PLATFORM': {
    'DARWIN': {
      'CC': '/usr/bin/clang',
      'CPPDEFINES': ['DARWIN'],
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

# TODO: autodetect these:
variants = [{'PLATFORM': 'DARWIN', 'PROFILE': 'DEBUG'}]

append_types = ['CCFLAGS', 'CFLAGS', 'CPPDEFINES']
replace_types = ['CC']
targets = []

# defaults for all platforms
env.AppendUnique(CPPPATH=['#/include', '#/include/private'])

for vari in variants:
  platform = vari['PLATFORM']
  profile =  vari['PROFILE']
  build = 'static'
  variant = '%s-%s-%s' % (platform, profile, build)
  vdir = pjoin('build', variant)
  venv = env.Clone()

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

  lib = venv.SConscript('lib/SConscript', variant_dir=vdir, duplicate=0, exports='venv')
  targets.append(lib)

