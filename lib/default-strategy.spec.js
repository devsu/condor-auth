const Spy = require('jasmine-spy');
const DefaultStrategy = require('./default-strategy');

describe('DefaultStrategy', () => {
  let defaultStrategy, mapRoles;

  beforeEach(() => {
    mapRoles = Spy.create();
  });

  describe('constructor()', () => {
    it('should set the mapRoles method', () => {
      defaultStrategy = new DefaultStrategy(mapRoles);
      expect(defaultStrategy.mapRoles).toEqual(mapRoles);
    });
  });
});
