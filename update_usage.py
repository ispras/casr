#! /usr/bin/env python3

import re, sys, os
import subprocess
from subprocess import Popen, PIPE

with open('docs/usage.md') as f:
  content = f.read()

command = subprocess.run(["cargo", "build"])
if command.returncode != 0:
    print('Cargo build exited with code ' + command.returncode)

build_dir = os.path.dirname(os.path.realpath(__file__))
target_dir = os.path.join(build_dir, "target", "debug")

for p in os.listdir(target_dir):
    if p.startswith("casr-") and os.path.isfile(target := os.path.join(target_dir, p)) \
            and os.access(target, os.X_OK):
        command = Popen([target, "-h"], stdout=PIPE, stderr=PIPE)
        out, _ = command.communicate()
        output = str(out, 'utf-8', errors='ignore')
        splitted = output.split('\n\n')
        number_of_sections = len(splitted)
        if number_of_sections != 4 and number_of_sections != 3:
            print('Bad format in help message: ' + p)
            continue
        for i in range(1, number_of_sections):
            splitted[i] = '\n'.join(['    ' + line for line in splitted[i].split('\n') if line])
        new_message = '\n\n'.join(splitted) + '\n\n'
        content = re.sub(f'## {p}\n\n' + '(.|\n)*?\n\n' * number_of_sections, \
                         f'## {p}\n\n' + new_message, \
                         content)

with open('docs/usage.md', 'w') as f:
  f.write(content)
