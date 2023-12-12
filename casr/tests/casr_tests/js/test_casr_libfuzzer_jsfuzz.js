function bar(data) {
    if (data.length > 0 && data[0] > '1') {
        throw new Error('First');
    } else if (data.length > 1 && data[1] > '2') {
        throw new Error('Second');
    } else if (data.length > 2 && data[2] > '3') {
        throw new Error('Third');
    }   
}

function foo(data) {
    bar(data);
}

function fuzz(data) {
    foo(data);
}

module.exports = {
    fuzz
};

fuzz(process.argv[1]);
