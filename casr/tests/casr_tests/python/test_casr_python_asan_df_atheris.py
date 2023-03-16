#!/usr/bin/env python3

import atheris

with atheris.instrument_imports():
    import sys
    import cpp_module

def crash(data):
    return cpp_module.df()


def TestOneInput(data):
    crash(data)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
