const condorAuth = require('./index');
const Auth = require('./lib/auth');
const DefaultStrategy = require('./lib/default-strategy');
const Token = require('./lib/token');

describe('condor-auth', () => {
  it('should expose the Auth class', () => {
    expect(condorAuth.Auth).toEqual(Auth);
  });
  it('should expose the DefaultStrategy class', () => {
    expect(condorAuth.DefaultStrategy).toEqual(DefaultStrategy);
  });
  it('should expose the Token class', () => {
    expect(condorAuth.Token).toEqual(Token);
  });
});
