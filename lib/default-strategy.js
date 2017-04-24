const Token = require('./token');

module.exports = class {
  constructor(mapRoles) {
    this.mapRoles = mapRoles;
  }

  static decodeAndVerifyToken(context, options) {
    const tokenString = context.metadata.get('authorization')[0];
    if (tokenString) {
      // Token class will create and verify the token,
      // if the token is invalid, it will throw an exception.
      return new Token(tokenString, options);
    }
  }
};
