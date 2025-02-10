#!/bin/env lua

function f(a, b)
    a = a .. 'qwer'
    b = b * 123
    c = a / b
    return c
end

function g(a)
    a = a .. 'qwer'
    b = 123
    c = f(a, b)
    return c
end

function h()
    a = 'qwer'
    c = g(a)
    return c
end

print(h())
