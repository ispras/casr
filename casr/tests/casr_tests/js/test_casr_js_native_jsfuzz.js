const native_lib = require('bindings')('native')

function fuzz(data) {
    native_lib.foo();
}

module.exports = {
    fuzz
};

fuzz(process.argv[1]);
