var jws = require('jws');
var decode = require('./decode');

var verify = function(token, secret, cb) {
    var jwtObject;

    if (!token) throw new Error('JWT.verify: Missing token');
    if (!secret) throw new Error('JWT.verify: Missing secret');
    if (!cb) throw new Error('JWT.verify: Missing callback');

    try {
        jwtObject = decode(token);
    } catch(err) {
        return cb(false, err);
    }

    if (!jwtObject) throw new Error('JWT:verify: Malformed token header');
    if (!jwtObject.header || !jwtObject.header.alg) throw new Error('JWT:verify: Missing alg from token header');

    jws.createVerify({
        secret: secret,
        signature: token,
        algorithm: jwtObject.header.alg
    }).on('done', function(valid, obj) {
        cb(valid, obj);
    });
};

module.exports = verify;
