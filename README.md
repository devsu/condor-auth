# condor-auth

An authorization Middleware for [Condor](http://condorjs.com). **Condor** is a [GRPC Framework for node](https://github.com/devsu/condor-framework).

This module control access to **GRPC methods**, based on the **access rules** defined.

It has been thought to work with [JWTs](https://jwt.io/), but you can plug in any other ready to use or custom [strategy](#strategies).

## Installation

```bash
npm install --save condor-auth
```

## How to use

Two steps are needed for authorization to work:

- First we need to define how to obtain the user resources and roles from the token (or from anywhere else).
- Then we should define the permissions required to access each of the GRPC methods.

### 1. Mapping Roles 

By default, **condor-auth** expects a valid JWT token in the `authorization` metadata. It will verify that it's valid, and convert it to an object you can easily use.

Here's an example on how you would instantiate **condor-auth** and map the token to the roles. 

```js
const Condor = require('condor-framework');
const Auth = require('condor-auth').Auth;
const Greeter = require('./greeter');

const options = {
  'resourceId': 'my-grpc-service',
  'secretOrPublicKey': 'shhhhh',
};

const auth = new Auth(options, (context, token) => {
  // if 'authorization' metadata was received, is a valid token and could be verified 
  // using the received options, 'token' will contain a valid token object
  console.log('token', token);
  // do your magic here, to calculate the resources and roles the user has access to
  // You can get the information from the token (or from anywhere).
  // Then return an object with the information.
  return {
    'my-grpc-service': ['view-all'],
    'another-app': ['create', 'update-own', 'view-all'],
    'realm': ['admin', 'user'],
  };
});

// Then just initiate the server, and use the middleware
const app = new Condor()
  .addService('./protos/greeter.proto', 'myapp.Greeter', new Greeter())
  .use(auth.middleware)
  .start();
```

As you can see, you must return an object from the mapping method. This object should be a map with the resource names as the keys, and an array of roles as the values.

Some [strategies](#strategies) might provide their own mappers, so you don't need to write the `mapper` method.

## 2. Configuring Access Rules

By default, when no options are passed, it will try to read the access rules from `access-rules.json`. This file is where you configure all the access rules for your application.

The rules file should export an object, with the full names of the services as keys, and an optional `default` key which will be used for every method that is not defined in the file.

### Rules Example

This example will show you the available options:

```js
module.exports = {
  'default': '$authenticated',
  'myapp.Greeter': {
  	'sayHello': 'special',
  	'sayHelloOther': 'other-app:special',
  	'sayHelloRealm': 'realm:admin',
  	'sayHelloCustom': customValidation,
  	'sayHelloPublic': '$anonymous',
  	'sayHelloMultiple': ['special', 'realm:admin', customValidation],
  },
};

function customValidation (context, token) => {
	if (token.hasRole('myRole') && context.metadata.get('someKey')[0] === 'someValue') {
		return true; // allow to continue
	}
	return false; // deny access
}
```

Using these rules, we're telling the application:

- By default, for every method not defined in the file, the user must be authenticated (without taking into account any roles).
- `sayHello` requires the user to have the `special` role in this application. (`resourceId` option must be set, to determine the name of this application)
- `sayHelloOther` requires the user to have the `special` role in the `other-app` resource.
- `sayHelloRealm` requires the user to have the `admin` role in the `realm` resource.
- `sayHelloCustom` access will be calculated by the `customValidation` method.
- `sayHelloPublic` will be public (`$anonymous`)
- `sayHelloMultiple` shows how you can pass not only one but an array of options to authorize the call. In this example, to authorize the method we are requiring any of these 3 conditions:

  - The user to have the `special` role in this application
  - The user to have the `admin` role in the `realm` resource
  - The `customValidation` method to return true

### Rules Options

#### $anonynous and $authenticated

You can use `$authenticated` to enforce a user to be authenticated before accessing the method (without verifying any roles).

In the same manner, you can use `$anonymous` if you want to make a resource public.

#### Roles

If it's a role in the current application, you should just use the role name e.g. `special`. For this to work, you must pass the `resourceId` option when creating the `Auth` instance.

If it's a role of another application/resource, use the resource name and the role name. e.g. `another-app:special`.

#### Custom Validation

For custom validation, just pass the function (make sure to pass the actual function, not only the function name).

The validation function will be called with two parameters: 

- `context`: The context being processed.
- `token`: The token that we received from the caller if any, null otherwise.

The validation function must return a truthy value to allow access. Any falsy value will deny access.

#### Multiple options for a method

You can pass not only one option, but an array of options to authorize the call. If any of them pass, the call will be authorized.

## Options

All values are optional. Their default values are:

| Option             | Description                                                            | Default         |
|--------------------|------------------------------------------------------------------------|-----------------|
| resourceId         | The name of the application                                            |                 |
| rulesFile          | The path to the rules file                                             | access-rules.js |
| secretOrPublicKey  | The key that should be used to verify a token                          |                 |
| strategy           | The strategy to use (if you don't want to use the default strategy)    |                 |

Also, it will accept any options of the [verify](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback) method of the [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) module. Such options will be used to verify the token.

## Strategies

Strategies allow you to customize:

- How the tokens are verified and decoded
- How the tokens are mapped to roles

**condor-auth** provides a default strategy for verifying and decoding JWTs, as shown in the example above.

Other known strategies are:

- [condor-auth-keycloak](https://github.com/devsu/condor-auth-keycloak)

## How to call from a client

The caller should include the `authorization` metadata, with a valid JWT.

```js
const grpc = require('grpc');
const jwt = require('jsonwebtoken');

const proto = grpc.load('./protos/greeter.proto');
const client = proto.myapp.Greeter('127.0.0.1:3000', grpc.credentials.createInsecure());

const myJWT = jwt.sign({ roles: 'myRole' }, 'shhhhh');

const data = {'name': 'Peter'};
const metadata = new grpc.Metadata();
metadata.set('authorization', myJWT);

client.sayHello(data, (err, result) => {
  console.log('err', err);
  console.log('result', result);
});
```

## License and Credits

MIT License. Copyright 2017 

Built by the [GRPC experts](https://devsu.com) at Devsu.
