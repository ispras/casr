function bar() {
    new Function(`
        throw new Error('internal');
    `)();
}

function foo() {
    bar();
}

function main() {
    foo();
}

main()
