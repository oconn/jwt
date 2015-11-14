var jws = require('jws');

function determinAlgorithm(alg) {
    return jws.ALGORITHMS.indexOf(alg) === -1 ? 'HS256' : alg;
}

var sign = function(secret, options, cb) {

    // Set arguments
    var args = [];

    for (var i = 0; i < arguments.length; i++) {
        args.push(arguments[i]);
    }

    secret = args.shift();
    cb = args.pop();
    options = args.shift() || {};

    if (!secret) throw new Error('JWT.sign: Missing secret');
    if (!cb) throw new Error('JWT.sign: Missing callback');

    var header = {
        alg: determinAlgorithm(options.alg),
        typ: 'JWT'
    };

    jws.createSign({
        header: header,
        secret: secret,
        payload: JSON.stringify(options.payload || {})
    }).on('done', function(signiture) {
        cb(signiture);
    });
};

module.exports = sign;
