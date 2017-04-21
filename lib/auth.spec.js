const grpc = require('grpc');
const Spy = require('jasmine-spy');
const Auth = require('./auth');
const DefaultStrategy = require('./default-strategy');
const errors = require('./errors.json');
const TokenTestHelper = require('../spec/tokenHelper');
const ContextHelper = require('../spec/contextHelper');
const RulesHelper = require('../spec/rulesHelper');

describe('Auth', () => {
  let auth, strategy, options, next, mapPermissions, decodeAndVerifyToken, tokenHelper,
    contextHelper, rulesHelper, originalConsoleError;

  beforeAll(() => {
    originalConsoleError = console.error;
  });

  afterAll(() => {
    console.error = originalConsoleError;
  });

  beforeEach((done) => {
    tokenHelper = new TokenTestHelper();
    contextHelper = new ContextHelper();
    rulesHelper = new RulesHelper();
    console.error = Spy.create();
    options = {};
    strategy = {'mapPermissions': Spy.create()};
    mapPermissions = Spy.create();
    decodeAndVerifyToken = Spy.create();
    next = Spy.resolve();
    Promise.all([
      rulesHelper.createRulesFile(),
    ]).then(done).catch(done.fail);
  });

  afterEach((done) => {
    Promise.all([
      rulesHelper.removeRulesFiles(),
    ]).then(done).catch(done);
  });

  describe('constructor()', () => {
    beforeEach(() => {
      rulesHelper.clearRequireCache();
    });

    describe('with mapPermissionsMethod', () => {
      it('should set the default strategy with the method passed', () => {
        auth = new Auth(mapPermissions);
        expect(auth.strategy instanceof DefaultStrategy).toBeTruthy();
        expect(auth.strategy.mapPermissions).toEqual(mapPermissions);
      });

      describe('with invalid mapPermissions method', () => {
        it('should throw an error', () => {
          expect(() => {
            auth = new Auth(1234);
          }).toThrowError(errors.MAPPING_METHOD_REQUIRED);
        });
      });
    });

    describe('with strategy object', () => {
      it('should set the strategy passed', () => {
        auth = new Auth(strategy);
        expect(auth.strategy).toEqual(strategy);
      });

      describe('without strategy.mapPermissions', () => {
        beforeEach(() => {
          delete strategy.mapPermissions;
        });
        it('should throw an error', () => {
          expect(() => {
            auth = new Auth(strategy, options);
          }).toThrowError(errors.MAPPING_METHOD_REQUIRED);
        });
      });

      describe('invalid strategy.mapPermissions', () => {
        beforeEach(() => {
          strategy.mapPermissions = 1234;
        });
        it('should throw an error', () => {
          expect(() => {
            auth = new Auth(strategy, options);
          }).toThrowError(errors.MAPPING_METHOD_REQUIRED);
        });
      });

      describe('with strategy.decodeAndVerifyToken', () => {
        beforeEach(() => {
          strategy.decodeAndVerifyToken = decodeAndVerifyToken;
        });
        it('should not change the method', () => {
          auth = new Auth(strategy, options);
          expect(auth.strategy.decodeAndVerifyToken).toEqual(decodeAndVerifyToken);
        });
      });

      describe('without strategy.decodeAndVerifyToken', () => {
        beforeEach(() => {
          delete strategy.decodeAndVerifyToken;
        });
        it('should use the default method', () => {
          auth = new Auth(strategy, options);
          expect(auth.strategy.decodeAndVerifyToken).toEqual(DefaultStrategy.decodeAndVerifyToken);
        });
      });
    });

    describe('without mapPermissionsMethod or strategy', () => {
      it('should throw an error', () => {
        expect(() => {
          auth = new Auth();
        }).toThrowError(errors.MAPPING_METHOD_REQUIRED);
      });
    });

    describe('without options', () => {
      it('should read rules from access-rules.js', () => {
        // Hacky way of testing
        /* eslint-disable no-underscore-dangle */
        const originalFileLoad = Auth.prototype._loadFile;
        Auth.prototype._loadFile = Spy.returnValue({});
        auth = new Auth(mapPermissions);
        expect(auth._loadFile).toHaveBeenCalledTimes(1);
        expect(auth._loadFile).toHaveBeenCalledWith('access-rules.js');
        Auth.prototype._loadFile = originalFileLoad;
        /* eslint-enable no-underscore-dangle */
      });

      describe('when access-rules.js file is not present', () => {
        beforeEach((done) => {
          rulesHelper.removeRulesFiles().then(done).catch(done.fail);
        });

        it('should throw an error', () => {
          expect(() => {
            auth = new Auth(mapPermissions);
          }).toThrowError(/access-rules\.js/g);
        });
      });
    });

    describe('with options', () => {
      beforeEach(() => {
        options = {'foo': 'baz'};
      });

      it('should add options to default options', () => {
        auth = new Auth(mapPermissions, options);
        expect(auth.options).toEqual(jasmine.objectContaining(options));
      });
    });

    describe('options: "rulesFile"', () => {
      beforeEach(() => {
        options = {'rulesFile': 'whatever.js'};
      });

      it('should try to read the configuration from such file', () => {
        // Hacky way of testing
        /* eslint-disable no-underscore-dangle */
        const originalFileLoad = Auth.prototype._loadFile;
        Auth.prototype._loadFile = Spy.returnValue({});
        auth = new Auth(mapPermissions, options);
        expect(auth._loadFile).toHaveBeenCalledTimes(1);
        expect(auth._loadFile).toHaveBeenCalledWith('whatever.js');
        Auth.prototype._loadFile = originalFileLoad;
        /* eslint-enable no-underscore-dangle */
      });
    });

    describe('options: "rules"', () => {
      beforeEach(() => {
        options = {'rules': {'foo': 'bar'}};
      });
      it('should use the passed rules instead of reading a file', () => {
        auth = new Auth(mapPermissions, options);
        expect(options.rules).toEqual(options.rules);
      });
    });

    it('should optimize rules', () => {
      const customValidator = Spy.create();
      const rules = {
        'default': '$authenticated',
        'another': ['$anonymous'],
        'my.app.Service': {
          'myMethod': 'asd',
          'another': customValidator,
          'yetAnother': ['asd:asd', customValidator],
        },
      };
      const expectedRules = [];
      expectedRules.default = ['$authenticated'];
      expectedRules.another = ['$anonymous'];
      expectedRules['my.app.Service'] = [];
      expectedRules['my.app.Service'].myMethod = ['asd'];
      expectedRules['my.app.Service'].another = [customValidator];
      expectedRules['my.app.Service'].yetAnother = ['asd:asd', customValidator];
      options = {rules};
      auth = new Auth(mapPermissions, options);
      expect(auth.rules).toEqual(expectedRules);
    });
  });

  describe('middleware()', () => {
    describe('without authorization metadata', () => {
      beforeEach(() => {
        options.rules = {'default': '$anonymous'};
        auth = new Auth(mapPermissions, options);
        contextHelper.setupEmptyContext();
      });

      it('should NOT attach any token to the context', () => {
        auth.middleware(contextHelper.context, next);
        expect(contextHelper.context.token).toBeUndefined();
      });

      it('should NOT log anything in the console', () => {
        auth.middleware(contextHelper.context, next);
        expect(console.error).not.toHaveBeenCalled();
      });
    });

    describe('with invalid authorization metadata', () => {
      beforeEach(() => {
        tokenHelper.setupValidToken();
        options = {
          'secretOrPublicKey': tokenHelper.keys.toPublicPem('utf8'),
          'rules': {'default': '$anonymous'},
        };
        auth = new Auth(mapPermissions, options);
        contextHelper.setupValidContext('invalid token');
      });

      it('should NOT attach any token to the context', () => {
        auth.middleware(contextHelper.context, next);
        expect(contextHelper.context.token).toBeUndefined();
      });

      it('should log the error to the console', () => {
        auth.middleware(contextHelper.context, next);
        expect(console.error).toHaveBeenCalledTimes(1);
        expect(console.error).toHaveBeenCalledWith('Invalid access token', jasmine.any(Error));
      });
    });

    describe('with valid authorization metadata', () => {
      beforeEach(() => {
        tokenHelper.setupValidToken();
        options = {'secretOrPublicKey': tokenHelper.keys.toPublicPem('utf8')};
      });

      describe('with Bearer prefix', () => {
        beforeEach(() => {
          auth = new Auth(mapPermissions, options);
          contextHelper.setupValidContext(tokenHelper.bearerTokenString);
        });

        it('should call the corresponding mapping method', () => {
          auth.middleware(contextHelper.context, next);
          verifyMappingMethodWasCalled(mapPermissions);
        });

        runTestsWithValidToken();
      });

      describe('without Bearer prefix', () => {
        beforeEach(() => {
          auth = new Auth(mapPermissions, options);
          contextHelper.setupValidContext(tokenHelper.tokenString);
        });

        it('should call the corresponding mapping method', () => {
          auth.middleware(contextHelper.context, next);
          verifyMappingMethodWasCalled(mapPermissions);
        });

        runTestsWithValidToken();
      });

      describe('when passing the strategy object', () => {
        let strategy;

        beforeEach(() => {
          strategy = {'mapPermissions': Spy.create()};
          auth = new Auth(strategy, options);
          contextHelper.setupValidContext(tokenHelper.tokenString);
        });

        it('should call the corresponding mapping method', () => {
          auth.middleware(contextHelper.context, next);
          verifyMappingMethodWasCalled(strategy.mapPermissions);
        });

        runTestsWithValidToken();
      });

      function runTestsWithValidToken() {
        it('should attach the token to the context', () => {
          auth.middleware(contextHelper.context, next);
          tokenHelper.verifyToken(contextHelper.context.token);
        });
      }

      function verifyMappingMethodWasCalled(mapPermissionsMethod) {
        expect(mapPermissionsMethod).toHaveBeenCalledTimes(1);
        expect(mapPermissionsMethod).toHaveBeenCalledWith(contextHelper.context,
          jasmine.objectContaining({
            'header': tokenHelper.header,
            'payload': jasmine.objectContaining(tokenHelper.payload),
            'signature': tokenHelper.signature,
          }));
      }
    });

    it('should call isAllowed with the right parameters', () => {
      const permissions = {'a': 'z'};
      const context = {'c': 'd'};
      mapPermissions.and.returnValue(permissions);
      auth = new Auth(mapPermissions, options);
      auth.isAllowed = Spy.returnValue(true);
      auth.middleware(context, next);
      expect(auth.isAllowed).toHaveBeenCalledTimes(1);
      expect(auth.isAllowed).toHaveBeenCalledWith(context, permissions);
    });

    describe('when isAllowed', () => {
      beforeEach(() => {
        auth = new Auth(mapPermissions, options);
        contextHelper.setupEmptyContext();
        auth.isAllowed = Spy.returnValue(true);
      });
      it('should call next', () => {
        auth.middleware(contextHelper.context, next);
        expect(next).toHaveBeenCalledTimes(1);
      });
    });

    describe('when is not allowed', () => {
      beforeEach(() => {
        auth = new Auth(mapPermissions, options);
        contextHelper.setupEmptyContext();
        auth.isAllowed = Spy.returnValue(false);
      });

      it('should not call next', () => {
        try {
          auth.middleware(contextHelper.context, next);
          fail();
        } catch (e) {
          expect(next).not.toHaveBeenCalled();
        }
      });

      describe('when user does not have a token', () => {
        beforeEach(() => {
          auth.strategy.decodeAndVerifyToken = Spy.throwError('invalid token');
        });
        it('should throw error with code: Unauthenticated', () => {
          try {
            auth.middleware(contextHelper.context, next);
            fail();
          } catch (e) {
            expect(e.code).toEqual(grpc.status.UNAUTHENTICATED);
            expect(e.details).toEqual('Unauthenticated');
          }
        });
      });

      describe('when user has a token', () => {
        beforeEach(() => {
          auth.strategy.decodeAndVerifyToken = Spy.returnValue({});
        });
        it('should throw error with code: PermissionDenied', () => {
          try {
            auth.middleware(contextHelper.context, next);
            fail();
          } catch (e) {
            expect(e.code).toEqual(grpc.status.PERMISSION_DENIED);
            expect(e.details).toEqual('Permission Denied');
          }
        });
      });
    });
  });

  describe('isAllowed()', () => {
    let serviceFullName, methodName, methodFullName, permissions, context, properties;

    beforeEach(() => {
      serviceFullName = 'myapp.Greeter';
      methodName = 'sayHello';
      methodFullName = `${serviceFullName}.${methodName}`;
      properties = {serviceFullName, methodName, methodFullName};
      context = {properties};
      options.rules = {};
      options.rules[serviceFullName] = {};
      permissions = {};
    });

    describe('resource is NOT defined in the rules', () => {
      beforeEach(() => {
        delete options.rules[serviceFullName];
      });
      it('should not fail', () => {
        auth = new Auth(mapPermissions, options);
        auth.isAllowed(context, permissions);
      });
    });

    describe('method is NOT defined in the rules', () => {
      describe('default is defined', () => {
        it('should calculate access using the default rule', () => {
          // 1
          options.rules = {'default': '$authenticated'};
          auth = new Auth(mapPermissions, options);
          context.token = {};
          expect(auth.isAllowed(context, permissions)).toBeTruthy();
          // 2
          options.rules = {'default': '$authenticated'};
          auth = new Auth(mapPermissions, options);
          delete context.token;
          expect(auth.isAllowed(context, permissions)).toBeFalsy();
          // 3
          options.rules = {'default': '$anonymous'};
          auth = new Auth(mapPermissions, options);
          expect(auth.isAllowed(context, permissions)).toBeTruthy();
          // 4
          options.rules = {'default': 'ffff'};
          auth = new Auth(mapPermissions, options);
          permissions = {};
          expect(auth.isAllowed(context, permissions)).toBeFalsy();
        });
      });
      describe('default is NOT defined', () => {
        // By default we deny access
        it('should deny access', () => {
          auth = new Auth(mapPermissions, options);
          expect(auth.isAllowed(context, permissions)).toBeFalsy();
        });
      });
    });

    describe('rule: $anonymous', () => {
      beforeEach(() => {
        options.rules[serviceFullName][methodName] = '$anonymous';
        auth = new Auth(mapPermissions, options);
      });
      it('should allow access', () => {
        expect(auth.isAllowed(context, permissions)).toBeTruthy();
      });
    });

    describe('rule: $authenticated', () => {
      beforeEach(() => {
        options.rules[serviceFullName][methodName] = '$authenticated';
        auth = new Auth(mapPermissions, options);
      });
      describe('user is authenticated', () => {
        beforeEach(() => {
          context.token = {};
        });
        it('should allow access', () => {
          expect(auth.isAllowed(context, permissions)).toBeTruthy();
        });
      });
      describe('user is NOT authenticated', () => {
        beforeEach(() => {
          delete context.token;
        });
        it('should NOT allow access', () => {
          expect(auth.isAllowed(context, permissions)).toBeFalsy();
        });
      });
    });

    describe('rule: role', () => {
      beforeEach(() => {
        options.rules[serviceFullName][methodName] = 'role1';
        auth = new Auth(mapPermissions, options);
      });
      describe('with options.applicationName', () => {
        beforeEach(() => {
          auth.options.applicationName = 'my-app';
        });
        describe('user has permission', () => {
          beforeEach(() => {
            permissions = {'my-app': 'role1'};
          });
          it('should allow access', () => {
            expect(auth.isAllowed(context, permissions)).toBeTruthy();
          });
        });
        describe('user does NOT have permission', () => {
          it('should deny access', () => {
            expect(auth.isAllowed(context, permissions)).toBeFalsy();
          });
        });
      });
      describe('without options.applicationName', () => {
        // TODO: We should launch a warning in the constructor if we detect this scenario
        it('should deny access', () => {
          expect(auth.isAllowed(context, permissions)).toBeFalsy();
        });
      });
    });

    describe('rule: resource:role', () => {
      beforeEach(() => {
        options.rules[serviceFullName][methodName] = 'my-resource:role1';
        auth = new Auth(mapPermissions, options);
      });
      describe('user has permission', () => {
        beforeEach(() => {
          permissions = {'my-resource': 'role1'};
        });
        it('should allow access', () => {
          expect(auth.isAllowed(context, permissions)).toBeTruthy();
        });
      });
      describe('user does NOT have permission', () => {
        it('should deny access', () => {
          expect(auth.isAllowed(context, permissions)).toBeFalsy();
        });
      });
    });

    describe('rule: Function()', () => {
      let customValidator;
      beforeEach(() => {
        customValidator = Spy.create();
        options.rules[serviceFullName][methodName] = customValidator;
        auth = new Auth(mapPermissions, options);
      });
      it('should call the validator with the context and token', () => {
        auth.isAllowed(context, permissions);
        expect(customValidator).toHaveBeenCalledTimes(1);
        expect(customValidator).toHaveBeenCalledWith(context, auth.token);
      });
      it('should return the same value the function returns', () => {
        customValidator.and.returnValue(true);
        expect(auth.isAllowed(context, permissions)).toEqual(true);
        customValidator.and.returnValue(false);
        expect(auth.isAllowed(context, permissions)).toEqual(false);
      });
      describe('when function throws an error', () => {
        it('should log the error (in debug mode)', () => {
          // TODO: Debug messages ?
        });
        it('should deny access', () => {
          customValidator.and.throwError('whatever');
          expect(auth.isAllowed(context, permissions)).toEqual(false);
        });
      });
    });

    describe('rule: Array', () => {
      beforeEach(() => {
        options.rules[serviceFullName][methodName] = ['app:a', 'other:b'];
        auth = new Auth(mapPermissions, options);
      });
      describe('at least one of the rules pass', () => {
        beforeEach(() => {
          permissions = {'other': 'b'};
        });
        it('should allow access', () => {
          expect(auth.isAllowed(context, permissions)).toBeTruthy();
        });
      });
      describe('no rule passes', () => {
        it('should deny access', () => {
          expect(auth.isAllowed(context, permissions)).toBeFalsy();
        });
      });
    });
  });
});
