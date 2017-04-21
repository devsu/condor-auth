const Token = require('./token');
const errors = require('./errors.json');

module.exports = class {
  constructor(mapPermissions) {
    if (!mapPermissions) {
      throw new Error(errors.MAPPING_METHOD_REQUIRED);
    }
    this.mapPermissions = mapPermissions;
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
