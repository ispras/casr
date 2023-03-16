#!/usr/bin/env python3

import cpp_module

def crash():
    return cpp_module.df()


def main():
    crash()


if __name__ == "__main__":
    main()
