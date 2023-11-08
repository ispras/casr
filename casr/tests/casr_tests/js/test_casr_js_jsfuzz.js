function bar() {
    new Function(`
        throw new Error('internal');
    `)();
}

function foo() {
    bar();
}

function fuzz(data) {
    foo();
}

module.exports = {
    fuzz
};

fuzz(process.argv[1]);
