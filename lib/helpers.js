/**
 * Pulls the JWT token out of the req header
 *
 * @param {Object} req
 * @function getJWT
 * @return {String|null}
 */
module.exports.getJWT = function(req) {
    var authHeader = req.headers && req.headers.authorization;

    // No Auth header
    if (!authHeader) return null;

    // No Bearer Token
    if (!/^Bearer /.test(authHeader)) return null;

    return authHeader.replace('Bearer ', '');
};
