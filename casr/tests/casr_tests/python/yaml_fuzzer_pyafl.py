#!/usr/bin/python3

# Copyright 2020 Google LLC
# Copyright 2021 Fraunhofer FKIE
# Modifications copyright (C) 2022 ISP RAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

import afl, sys, os
from ruamel import yaml as ruamel_yaml
import warnings

# Suppress all warnings.
warnings.simplefilter("ignore")

def _ConsumeString(res_len, data):
    s = ""
    if len(data) == 0:
        return s

    if data[0]&1:
        res_len = min(res_len, len(data))
        amt_b = res_len

        for i in range(0, amt_b, 1):
            cur = 0
            for j in range(0, 1):
                cur <<= 8
                cur += data[i+j]
            s += chr(cur)
    elif data[0]&2:
        res_len = min(res_len, len(data) // 2)
        amt_b = res_len * 2

        for i in range(0, amt_b, 2):
            cur = 0
            for j in range(0, 2):
                cur <<= 8
                cur += data[i+j]
            s += chr(cur)
    else:
        res_len = min(res_len, len(data) // 4)
        amt_b = res_len * 4

        for i in range(0, amt_b, 4):
            cur = 0
            for j in range(0, 4):
                cur <<= 8
                cur += data[i+j]
            cur &= 0x1fffff
            if cur&0x100000:
                cur &= ~0x0f0000
            s += chr(cur)
    return s

def TestOneInput(input_bytes):
  ryaml = ruamel_yaml.YAML(typ="safe", pure=True)
  ryaml.allow_duplicate_keys = True
  data = _ConsumeString(sys.maxsize, input_bytes)

  try:
    iterator = ryaml.load_all(data)
    for _ in iterator:
      pass
  except ruamel_yaml.error.YAMLError:
    return

  except Exception:
    input_type = str(type(data))
    codepoints = [hex(ord(x)) for x in data]
    sys.stderr.write(
        "Input was {input_type}: {data}\nCodepoints: {codepoints}".format(
            input_type=input_type, data=data, codepoints=codepoints))
    raise


def main():
  try:
    stdin_compat = sys.stdin.buffer
  except AttributeError:
    stdin_compat = sys.stdin

  while afl.loop(10000): 
    TestOneInput(stdin_compat.read())
    sys.stdin.seek(0)
  os._exit(0)


if __name__ == "__main__":
  main()
