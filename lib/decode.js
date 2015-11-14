var jws = require('jws');

var decode = function(token) {
    return jws.decode(token);
};

module.exports = decode;
