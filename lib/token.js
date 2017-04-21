const jwt = require('jsonwebtoken');
const errors = require('./errors.json');

module.exports = class {
  constructor(tokenString, options) {
    if (!tokenString) {
      throw new Error(errors.TOKEN_REQUIRED);
    }
    if (!options || !options.secretOrPublicKey) {
      throw new Error(errors.KEY_REQUIRED);
    }
    const cleanTokenString = this._cleanupTokenString(tokenString);
    const token = jwt.decode(cleanTokenString, {'complete': true});
    Object.assign(this, token);
    this.raw = cleanTokenString;
    jwt.verify(cleanTokenString, options.secretOrPublicKey, options);
  }

  _cleanupTokenString(tokenString) {
    if (tokenString.indexOf('Bearer ') === 0) {
      return tokenString.substring(7);
    }
    return tokenString;
  }
};
