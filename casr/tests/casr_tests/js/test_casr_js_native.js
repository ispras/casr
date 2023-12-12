#!/usr/bin/env node

const native_lib = require('bindings')('native')

native_lib.foo();
