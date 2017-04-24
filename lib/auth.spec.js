const grpc = require('grpc');
const Spy = require('jasmine-spy');
const Auth = require('./auth');
const DefaultStrategy = require('./default-strategy');
const errors = require('./errors.json');
const TokenTestHelper = require('../spec/tokenHelper');
const ContextHelper = require('../spec/contextHelper');
const RulesHelper = require('../spec/rulesHelper');

describe('Auth', () => {
  let auth, strategy, options, next, mapRoles, decodeAndVerifyToken, tokenHelper,
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
    strategy = {'mapRoles': Spy.create()};
    mapRoles = Spy.create();
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

    describe('with mapRoles method', () => {
      it('should set the default strategy with the method passed', () => {
        auth = new Auth(mapRoles);
        expect(auth.strategy instanceof DefaultStrategy).toBeTruthy();
        expect(auth.strategy.mapRoles).toEqual(mapRoles);
      });

      describe('with invalid mapRoles method', () => {
        it('should throw an error', () => {
          expect(() => {
            auth = new Auth(1234);
          }).toThrowError(errors.INVALID_MAPPING_ROLES_METHOD);
        });
      });
    });

    describe('with strategy object', () => {
      it('should set the strategy passed', () => {
        auth = new Auth(strategy);
        expect(auth.strategy).toEqual(strategy);
      });

      describe('without strategy.mapRoles', () => {
        beforeEach(() => {
          delete strategy.mapRoles;
        });
        it('should NOT throw an error', () => {
          expect(() => {
            auth = new Auth(strategy, options);
          }).not.toThrowError(errors.INVALID_MAPPING_ROLES_METHOD);
        });
      });

      describe('invalid strategy.mapRoles', () => {
        beforeEach(() => {
          strategy.mapRoles = 1234;
        });
        it('should throw an error', () => {
          expect(() => {
            auth = new Auth(strategy, options);
          }).toThrowError(errors.INVALID_MAPPING_ROLES_METHOD);
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

    describe('without mapRoles method or strategy', () => {
      it('should NOT throw an error', () => {
        expect(() => {
          auth = new Auth();
        }).not.toThrowError(errors.INVALID_MAPPING_ROLES_METHOD);
      });
    });

    describe('without options', () => {
      it('should read rules from access-rules.js', () => {
        // Hacky way of testing
        /* eslint-disable no-underscore-dangle */
        const originalFileLoad = Auth.prototype._loadFile;
        Auth.prototype._loadFile = Spy.returnValue({});
        auth = new Auth(mapRoles);
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
            auth = new Auth(mapRoles);
          }).toThrowError(/access-rules\.js/g);
        });
      });
    });

    describe('with options', () => {
      beforeEach(() => {
        options = {'foo': 'baz'};
      });

      it('should add options to default options', () => {
        auth = new Auth(mapRoles, options);
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
        auth = new Auth(mapRoles, options);
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
        auth = new Auth(mapRoles, options);
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
      auth = new Auth(mapRoles, options);
      expect(auth.rules).toEqual(expectedRules);
    });
  });

  describe('middleware()', () => {
    describe('without authorization metadata', () => {
      beforeEach(() => {
        options.rules = {'default': '$anonymous'};
        auth = new Auth(mapRoles, options);
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
        auth = new Auth(mapRoles, options);
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
          auth = new Auth(mapRoles, options);
          contextHelper.setupValidContext(tokenHelper.bearerTokenString);
        });

        it('should call the corresponding mapping method', () => {
          auth.middleware(contextHelper.context, next);
          verifyMappingMethodWasCalled(mapRoles);
        });

        runTestsWithValidToken();
      });

      describe('without Bearer prefix', () => {
        beforeEach(() => {
          auth = new Auth(mapRoles, options);
          contextHelper.setupValidContext(tokenHelper.tokenString);
        });

        it('should call the corresponding mapping method', () => {
          auth.middleware(contextHelper.context, next);
          verifyMappingMethodWasCalled(mapRoles);
        });

        runTestsWithValidToken();
      });

      describe('when passing the strategy object', () => {
        let strategy;

        beforeEach(() => {
          strategy = {'mapRoles': Spy.create()};
          auth = new Auth(strategy, options);
          contextHelper.setupValidContext(tokenHelper.tokenString);
        });

        it('should call the corresponding mapping method', () => {
          auth.middleware(contextHelper.context, next);
          verifyMappingMethodWasCalled(strategy.mapRoles);
        });

        runTestsWithValidToken();
      });

      function runTestsWithValidToken() {
        it('should attach the token to the context', () => {
          auth.middleware(contextHelper.context, next);
          tokenHelper.verifyToken(contextHelper.context.token);
        });
      }

      function verifyMappingMethodWasCalled(mapRolesMethod) {
        expect(mapRolesMethod).toHaveBeenCalledTimes(1);
        expect(mapRolesMethod).toHaveBeenCalledWith(contextHelper.context,
          jasmine.objectContaining({
            'header': tokenHelper.header,
            'payload': jasmine.objectContaining(tokenHelper.payload),
            'signature': tokenHelper.signature,
          }));
      }
    });

    it('should call isAllowed with the right parameters', () => {
      const roles = {'a': 'z'};
      const context = {'c': 'd'};
      mapRoles.and.returnValue(roles);
      auth = new Auth(mapRoles, options);
      auth.isAllowed = Spy.returnValue(true);
      auth.middleware(context, next);
      expect(auth.isAllowed).toHaveBeenCalledTimes(1);
      expect(auth.isAllowed).toHaveBeenCalledWith(context, roles);
    });

    describe('when constructed without mapRoles or strategy.mapRoles', () => {
      it('should call isAllowed with no roles set', () => {
        const context = {'c': 'd'};
        auth = new Auth();
        auth.isAllowed = Spy.returnValue(true);
        auth.middleware(context, next);
        expect(auth.isAllowed).toHaveBeenCalledTimes(1);
        expect(auth.isAllowed).toHaveBeenCalledWith(context, {});
      });
    });

    describe('when isAllowed', () => {
      beforeEach(() => {
        auth = new Auth(mapRoles, options);
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
        auth = new Auth(mapRoles, options);
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
    let serviceFullName, methodName, methodFullName, roles, context, properties;

    beforeEach(() => {
      serviceFullName = 'myapp.Greeter';
      methodName = 'sayHello';
      methodFullName = `${serviceFullName}.${methodName}`;
      properties = {serviceFullName, methodName, methodFullName};
      context = {properties};
      options.rules = {};
      options.rules[serviceFullName] = {};
      roles = {};
    });

    describe('resource is NOT defined in the rules', () => {
      beforeEach(() => {
        delete options.rules[serviceFullName];
      });
      it('should not fail', () => {
        auth = new Auth(mapRoles, options);
        auth.isAllowed(context, roles);
      });
    });

    describe('method is NOT defined in the rules', () => {
      describe('default is defined', () => {
        it('should calculate access using the default rule', () => {
          // 1
          options.rules = {'default': '$authenticated'};
          auth = new Auth(mapRoles, options);
          context.token = {};
          expect(auth.isAllowed(context, roles)).toBeTruthy();
          // 2
          options.rules = {'default': '$authenticated'};
          auth = new Auth(mapRoles, options);
          delete context.token;
          expect(auth.isAllowed(context, roles)).toBeFalsy();
          // 3
          options.rules = {'default': '$anonymous'};
          auth = new Auth(mapRoles, options);
          expect(auth.isAllowed(context, roles)).toBeTruthy();
          // 4
          options.rules = {'default': 'ffff'};
          auth = new Auth(mapRoles, options);
          roles = {};
          expect(auth.isAllowed(context, roles)).toBeFalsy();
        });
      });
      describe('default is NOT defined', () => {
        // By default we deny access
        it('should deny access', () => {
          auth = new Auth(mapRoles, options);
          expect(auth.isAllowed(context, roles)).toBeFalsy();
        });
      });
    });

    describe('rule: $anonymous', () => {
      beforeEach(() => {
        options.rules[serviceFullName][methodName] = '$anonymous';
        auth = new Auth(mapRoles, options);
      });
      it('should allow access', () => {
        expect(auth.isAllowed(context, roles)).toBeTruthy();
      });
    });

    describe('rule: $authenticated', () => {
      beforeEach(() => {
        options.rules[serviceFullName][methodName] = '$authenticated';
        auth = new Auth(mapRoles, options);
      });
      describe('user is authenticated', () => {
        beforeEach(() => {
          context.token = {};
        });
        it('should allow access', () => {
          expect(auth.isAllowed(context, roles)).toBeTruthy();
        });
      });
      describe('user is NOT authenticated', () => {
        beforeEach(() => {
          delete context.token;
        });
        it('should NOT allow access', () => {
          expect(auth.isAllowed(context, roles)).toBeFalsy();
        });
      });
    });

    describe('rule: role', () => {
      beforeEach(() => {
        options.rules[serviceFullName][methodName] = 'role1';
        auth = new Auth(mapRoles, options);
      });
      describe('with options.applicationName', () => {
        beforeEach(() => {
          auth.options.applicationName = 'my-app';
        });
        describe('user has role', () => {
          beforeEach(() => {
            roles = {'my-app': 'role1'};
          });
          it('should allow access', () => {
            expect(auth.isAllowed(context, roles)).toBeTruthy();
          });
        });
        describe('user does NOT have role', () => {
          it('should deny access', () => {
            expect(auth.isAllowed(context, roles)).toBeFalsy();
          });
        });
      });
      describe('without options.applicationName', () => {
        // TODO: We should launch a warning in the constructor if we detect this scenario
        it('should deny access', () => {
          expect(auth.isAllowed(context, roles)).toBeFalsy();
        });
      });
    });

    describe('rule: resource:role', () => {
      beforeEach(() => {
        options.rules[serviceFullName][methodName] = 'my-resource:role1';
        auth = new Auth(mapRoles, options);
      });
      describe('user has role', () => {
        beforeEach(() => {
          roles = {'my-resource': 'role1'};
        });
        it('should allow access', () => {
          expect(auth.isAllowed(context, roles)).toBeTruthy();
        });
      });
      describe('user does NOT have role', () => {
        it('should deny access', () => {
          expect(auth.isAllowed(context, roles)).toBeFalsy();
        });
      });
    });

    describe('rule: Function()', () => {
      let customValidator;
      beforeEach(() => {
        customValidator = Spy.create();
        options.rules[serviceFullName][methodName] = customValidator;
        auth = new Auth(mapRoles, options);
      });
      it('should call the validator with the context and token', () => {
        auth.isAllowed(context, roles);
        expect(customValidator).toHaveBeenCalledTimes(1);
        expect(customValidator).toHaveBeenCalledWith(context, auth.token);
      });
      it('should return the same value the function returns', () => {
        customValidator.and.returnValue(true);
        expect(auth.isAllowed(context, roles)).toEqual(true);
        customValidator.and.returnValue(false);
        expect(auth.isAllowed(context, roles)).toEqual(false);
      });
      describe('when function throws an error', () => {
        it('should log the error (in debug mode)', () => {
          // TODO: Debug messages ?
        });
        it('should deny access', () => {
          customValidator.and.throwError('whatever');
          expect(auth.isAllowed(context, roles)).toEqual(false);
        });
      });
    });

    describe('rule: Array', () => {
      beforeEach(() => {
        options.rules[serviceFullName][methodName] = ['app:a', 'other:b'];
        auth = new Auth(mapRoles, options);
      });
      describe('at least one of the rules pass', () => {
        beforeEach(() => {
          roles = {'other': 'b'};
        });
        it('should allow access', () => {
          expect(auth.isAllowed(context, roles)).toBeTruthy();
        });
      });
      describe('no rule passes', () => {
        it('should deny access', () => {
          expect(auth.isAllowed(context, roles)).toBeFalsy();
        });
      });
    });
  });
});
