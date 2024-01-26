const native_lib = require('bindings')('native')

function fuzz(data) {
    native_lib.foo();
}

module.exports.fuzz = function (data /*: Buffer */) {
    const fuzzerData = data.toString();
    fuzz(fuzzerData);
};
