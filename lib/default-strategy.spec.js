const Spy = require('jasmine-spy');
const DefaultStrategy = require('./default-strategy');
const errors = require('./errors.json');

describe('DefaultStrategy', () => {
  let defaultStrategy, mapPermissions;

  beforeEach(() => {
    mapPermissions = Spy.create();
  });

  describe('constructor()', () => {
    it('requires mapPermissions parameter', () => {
      expect(() => {
        defaultStrategy = new DefaultStrategy();
      }).toThrowError(errors.MAPPING_METHOD_REQUIRED);
    });
    it('should set the mapPermissions method', () => {
      defaultStrategy = new DefaultStrategy(mapPermissions);
      expect(defaultStrategy.mapPermissions).toEqual(mapPermissions);
    });
  });
});
