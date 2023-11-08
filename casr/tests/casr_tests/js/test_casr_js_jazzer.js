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

module.exports.fuzz = function (data /*: Buffer */) {
    const fuzzerData = data.toString();
    fuzz(fuzzerData);
};