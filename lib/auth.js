const grpc = require('grpc');
const path = require('path');
const DefaultStrategy = require('./default-strategy');
const errors = require('./errors.json');

const DEFAULT_OPTIONS = {
  'rulesFile': 'access-rules.js',
};

module.exports = class {
  constructor(strategy, options) {
    this.strategy = this._buildStrategy(strategy);
    this.options = this._buildOptions(options);
    this.rules = this._buildRules();
  }

  _buildStrategy(originalStrategy) {
    let strategy;
    if (originalStrategy instanceof Function) {
      strategy = new DefaultStrategy(originalStrategy);
    } else if (originalStrategy instanceof Object) {
      strategy = originalStrategy;
    } else if (originalStrategy) {
      throw new Error(errors.INVALID_MAPPING_ROLES_METHOD);
    }
    if (strategy && strategy.mapRoles && !(strategy.mapRoles instanceof Function)) {
      throw new Error(errors.INVALID_MAPPING_ROLES_METHOD);
    }
    if (!strategy) {
      strategy = {};
    }
    if (!strategy.mapRoles) {
      strategy.mapRoles = () => {
        return {};
      };
    }
    if (!strategy.decodeAndVerifyToken) {
      strategy.decodeAndVerifyToken = DefaultStrategy.decodeAndVerifyToken;
    }
    return strategy;
  }

  _buildOptions(options) {
    return Object.assign({}, DEFAULT_OPTIONS, options);
  }

  _buildRules() {
    const rules = this.options.rules || this._loadFile(this.options.rulesFile);
    const optimized = [];
    Object.keys(rules).forEach((serviceName) => {
      optimized[serviceName] = this._optimizeRules(rules[serviceName]);
    });
    return optimized;
  }

  _optimizeRules(rules) {
    // Optimizing for isAllowedMethod() to be faster
    // - Array is slightly faster than object
    // - All rules are converted to arrays, so we avoid checking type inside isAllowed()

    if (typeof rules === 'string' || rules instanceof String || rules instanceof Function) {
      return [rules];
    }
    if (Array.isArray(rules)) {
      return rules;
    }
    const rulesForMethod = [];
    Object.keys(rules).forEach((methodName) => {
      if (Array.isArray(rules[methodName])) {
        rulesForMethod[methodName] = rules[methodName];
        return;
      }
      rulesForMethod[methodName] = [rules[methodName]];
    });
    return rulesForMethod;
  }

  _loadFile(filePath) {
    return require(path.join(process.cwd(), filePath));
  }

  middleware(context, next) {
    try {
      context.token = this.strategy.decodeAndVerifyToken(context, this.options);
    } catch (error) {
      // TODO: Change to debug messages?
      console.error('Invalid access token', error);
    }
    const roles = this.strategy.mapRoles(context, context.token) || {};
    if (this.isAllowed(context, roles)) {
      return next();
    }
    if (context.token) {
      throw {
        'code': grpc.status.PERMISSION_DENIED,
        'details': 'Permission Denied',
      };
    }
    throw {
      'code': grpc.status.UNAUTHENTICATED,
      'details': 'Unauthenticated',
    };
  }

  isAllowed(context, roles) {
    const serviceFullName = context.properties.serviceFullName;
    const methodName = context.properties.methodName;
    const rulesFound = this._findRulesForMethod(serviceFullName, methodName);
    const matchingRule = rulesFound.find((rule) => {
      return this._ruleMatches(rule, roles, context);
    });
    return Boolean(matchingRule);
  }

  _findRulesForMethod(serviceFullName, methodName) {
    if (this.rules[serviceFullName] && this.rules[serviceFullName][methodName]) {
      return this.rules[serviceFullName][methodName];
    }
    if (this.rules.default) {
      return this.rules.default;
    }
    return [];
  }

  _ruleMatches(rule, roles, context) {
    if (rule === '$anonymous') {
      return true;
    }
    if (rule === '$authenticated' && context.token) {
      return true;
    }
    if (rule instanceof Function) {
      try {
        return rule.call(null, context, context.token);
      } catch (e) {
        return false;
      }
    }
    if (rule.indexOf(':') > 0) {
      const ruleParts = rule.split(':');
      if (roles[ruleParts[0]] === ruleParts[1]) {
        return true;
      }
    }
    return (roles[this.options.applicationName] === rule);
  }
};
