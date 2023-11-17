function bar(data) {
    if (data.length > 0 && data[0] > '1') {
        throw new TypeError('First');
    } else if (data.length > 1 && data[1] > '1') {
        throw new ReferenceError('Second');
    } else if (data.length > 2 && data[2] > '1') {
        throw new RangeError('Third');
    }   
}

function foo(data) {
    bar(data);
}

function fuzz(data) {
    foo(data);
}

module.exports.fuzz = function (data /*: Buffer */) {
    const fuzzerData = data.toString();
    fuzz(fuzzerData);
};