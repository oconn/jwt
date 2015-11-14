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
        return cb(new Error('JWT:verify: Malformed JWT'), null);
    }

    if (!jwtObject) {
        return cb(new Error('JWT:verify: Malformed token header'), null);
    }

    if (!jwtObject.header || !jwtObject.header.alg) {
        return cb(new Error('JWT:verify: Missing alg from token header'), null);
    }

    if (jwtObject.payload && jwtObject.payload.exp) {
        if (Math.floor(Date.now() / 1000) > jwtObject.payload.exp) {
            return cb(new Error('JWT Expired'), null);
        }
    }

    jws.createVerify({
        secret: secret,
        signature: token,
        algorithm: jwtObject.header.alg
    }).on('done', function(valid, obj) {
        if (!valid) {
            return cb(new Error('Invalid JWT'), null);
        }

        cb(null, obj);
    });
};

module.exports = verify;
