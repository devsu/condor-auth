const jwt = require('jsonwebtoken');
const Spy = require('jasmine-spy');
const Token = require('./token');
const errors = require('./errors.json');
const TokenTestHelper = require('../spec/tokenHelper');

describe('Token', () => {
  let tokenHelper, options, originalVerifyMethod, token;

  beforeEach(() => {
    originalVerifyMethod = jwt.verify;
    jwt.verify = Spy.create();
    tokenHelper = new TokenTestHelper();
  });

  afterEach(() => {
    jwt.verify = originalVerifyMethod;
  });

  describe('constructor()', () => {
    describe('no string token passed', () => {
      it('should throw an error', () => {
        expect(() => {
          token = new Token();
        }).toThrowError(errors.TOKEN_REQUIRED);
      });
    });

    describe('no options passed', () => {
      it('should throw an error', () => {
        expect(() => {
          token = new Token('my-token');
        }).toThrowError(errors.KEY_REQUIRED);
      });
    });

    describe('with valid token string', () => {
      beforeEach(() => {
        tokenHelper.setupValidToken();
        options = {
          'secretOrPublicKey': tokenHelper.keys.toPublicPem('utf8'),
        };
      });

      describe('without key to decode', () => {
        it('should throw an error', () => {
          delete options.secretOrPublicKey;
          expect(() => {
            token = new Token(tokenHelper.tokenString, options);
          }).toThrowError(errors.KEY_REQUIRED);
        });
      });

      it('should verify the token using jwt module', () => {
        // we are tied to this module, since jws doesn't offer all the validation options
        token = new Token(tokenHelper.tokenString, options);
        expect(jwt.verify).toHaveBeenCalledTimes(1);
        expect(jwt.verify).toHaveBeenCalledWith(tokenHelper.tokenString,
          options.secretOrPublicKey, options);
      });

      describe('when the verification fails', () => {
        beforeEach(() => {
          jwt.verify = Spy.throwError('something went wrong');
        });
        it('should fail with the error', () => {
          expect(() => {
            token = new Token(tokenHelper.tokenString, options);
          }).toThrowError('something went wrong');
        });
      });

      describe('when the verification is successful', () => {
        beforeEach(() => {
          jwt.verify = Spy.returnValue(tokenHelper.payload);
        });
        it('should return a token object with the information decoded', () => {
          token = new Token(tokenHelper.tokenString, options);
          expect(token.header).toEqual(tokenHelper.header);
          expect(token.payload).toEqual(jasmine.objectContaining(tokenHelper.payload));
          expect(token.signature).toEqual(tokenHelper.signature);
        });

        it('should set the raw property with the token string', () => {
          token = new Token(tokenHelper.tokenString, options);
          expect(token.raw).toEqual(tokenHelper.tokenString);
        });
      });
    });

    describe('with valid token string with "Bearer " prefix', () => {
      beforeEach(() => {
        tokenHelper.setupValidToken();
        options = {
          'secretOrPublicKey': tokenHelper.keys.toPublicPem('utf8'),
        };
      });
      it('should work removing the bearer prefix', () => {
        token = new Token(tokenHelper.bearerTokenString, options);
        expect(token.header).toEqual(tokenHelper.header);
        expect(token.payload).toEqual(jasmine.objectContaining(tokenHelper.payload));
        expect(token.signature).toEqual(tokenHelper.signature);
        expect(token.raw).toEqual(tokenHelper.tokenString);
      });
    });
  });
});
