# condor-auth

An authorization Middleware for [Condor](http://condorjs.com). **Condor** is a [GRPC Framework for node](https://github.com/devsu/condor-framework).

This module control access to **GRPC methods**, based on the **access rules** defined.

It has been thought to work with [JWTs](https://jwt.io/), but you can plug in any other [strategy](#strategies).

## Installation

```bash
npm install --save condor-framework
npm install --save condor-auth
```

## How to use

By default, this module is designed to work with **JWts** and **role-based** authorization. Anyways, it's flexible enough to allow any other authorization [strategy](#strategies).

### Role-based authorization

Two steps are needed for role-based authorization to work:

- [1. Map the roles](#1-mapping-roles): Define how to obtain the roles from the token (or from anywhere else).
- [2. Configure access rules](#2-configuring-access-rules): Define the roles required to access each of the GRPC methods.

### Resource-based authorization

For resource based authorization, you can skip step one, and just use **custom validators** when defining the [access rules](#2-configuring-access-rules).

### 1. Mapping Roles 

By default, **condor-auth** expects a valid JWT token in the `authorization` metadata. It will verify it, and convert it to an object you can easily use.

Then, you need to define how to map the information in the token to the roles the user has. 

Let's say for example, that the user has the `admin` role in `my-grpc-application`, and the `user` roles in `another-app`.

Here's an example on how you would instantiate **condor-auth** and map the permissions. 

```js
// index.js

const Condor = require('condor-framework');
const Auth = require('condor-auth').Auth;
const Greeter = require('./greeter');

// Options must contain any information required to verify the token (see documentation below)
const options = {
  'applicationName': 'my-grpc-service',
  'secretOrPublicKey': 'shhhhh',
};

const auth = new Auth((context, token) => {
  // if 'authorization' metadata was received, is a valid token and could be verified 
  // using the received options, 'token' will contain a valid token object
  console.log('token', token);
  // do your magic here, to calculate the resources and roles the user has access to
  // You can get the information from the token (or from anywhere).
  // Then return an object with the information.
  return {
    'my-grpc-service': ['admin'],
    'another-app': ['user', 'another-role'],
    'realm': ['admin', 'user', 'yet-another-role'],
  };
}, options);

// Then just initiate the server, and use the middleware
const app = new Condor()
  .addService('./protos/greeter.proto', 'myapp.Greeter', new Greeter())
  .use(auth.middleware)
  .start();
```

As you can see, the mapping method must return an object. This object should be a map with the resource names as the keys, and an array of roles as the values.

## 2. Configuring Access Rules

After mapping the roles, you will need to define the rules to access each of the methods in your GRPC service.

By default, when no options are passed, it will try to read the access rules from `access-rules.js`. This file is where you configure all the access rules for your application.

The rules file should export an object, with the full names of the services as keys, and an optional `default` key which will be used for every method that is not defined in the file.

### Rules Example

This example will show you the available options:

```js
// access-rules.js

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
- `sayHello` requires the user to have the `special` permission/role in this application. (`applicationName` option must be set, to determine the name of this application)
- `sayHelloOther` requires the user to have the `special` permission/role in the `other-app` resource.
- `sayHelloRealm` requires the user to have the `admin` permission/role in the `realm` resource.
- `sayHelloCustom` access will be calculated by the `customValidation` method.
- `sayHelloPublic` will be public (`$anonymous`)
- `sayHelloMultiple` shows how you can pass not only one but an array of options to authorize the call. In this example, to authorize the method we are requiring any of these 3 conditions:

  - The user to have the `special` permission/role in this application
  - The user to have the `admin` permission/role in the `realm` resource
  - The `customValidation` method to return true

### Rules Options

#### $anonynous and $authenticated

You can use `$authenticated` to enforce a user to be authenticated before accessing the method (without verifying any roles). A user is considered authenticated when the token received in the metadata is valid.

On the other hand, you can use `$anonymous` to make a resource public.

#### Role and Resource:Role

If it's a role in the current application, you can just use the permission/role name e.g. `special`. For this to work, you must pass the `applicationName` option when creating the `Auth` instance.

If it's a permission or role of another application/resource, use the resource name and the role/permission name. e.g. `another-app:special`.

#### Custom Validators

If you need some specific logic to authorize/deny access, just pass the function that must perform the validation (make sure to pass the actual function, not only the function name).

The validation function will be called with two parameters: 

- `context`: The context being processed.
- `token`: The decoded token if any, null otherwise.

The validation function must return a truthy value to allow access. Any falsy value will deny access.

#### Multiple options for a method

You can pass not only one option, but an array of options to authorize the call. If any of them pass, the call will be authorized.

#### How to require two roles? (use AND instead of OR)

The module is designed for the most common scenario, but we're sure there will be cases where your requirements will be different, in that case you can use custom validation functions that do exactly what you want. You can have for example something like this:
 
 ```js
 module.exports = {
   'default': '$authenticated',
   'myapp.Greeter': {
   	'sayHelloCustom': tokenHasAllRoles('special', 'admin'),
   },
 };
 
function tokenHasAllRoles() {
  const roles = arguments;
  return (context, token) => {
    // Verify that the token has all the roles
    return roles.every((role) => {
      return token.payload.roles.contains(role);
    });
  };
}
 ```

## Options

All values are optional. Their default values are:

| Option             | Description                                                                                            | Default         |
|--------------------|--------------------------------------------------------------------------------------------------------|-----------------|
| applicationName    | The name of the application. To allow rules like 'my-role', instead of 'my-app:my-role')               |                 |
| rulesFile          | The path to the rules file                                                                             | access-rules.js |
| rules              | The access rules to use (can be used instead of rulesFile)                                             |                 |
| secretOrPublicKey  | The key that should be used to verify a token                                                          |                 |
| strategy           | The strategy to use (if you don't want to use the default strategy)                                    |                 |

Also, it will accept any options of the [verify](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback) method of the [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) module. Such options will be used to verify the token.

## Strategies

Strategies allow you to customize:

- How the tokens are verified and decoded
- How the tokens are mapped to roles

Known strategies are:

- **Default strategy**: Bundled. It decodes and verifies JWTs using [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) module. It doesn't provide a mapping method.
- **[condor-auth-keycloak](https://github.com/devsu/condor-auth-keycloak)**. It verifies the token against keycloak, and map realm roles and resources roles automatically.

## How to call from a client

The caller just need to include the `authorization` metadata, with a valid JWT.

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
