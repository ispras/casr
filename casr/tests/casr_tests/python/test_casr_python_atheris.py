#!/usr/bin/env python3

import atheris

with atheris.instrument_imports():
    import sys


def crash_found(data):
    return 1/0


def TestOneInput(data):
    crash_found(data)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
