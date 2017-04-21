const grpc = require('grpc');

module.exports = class {
  setupEmptyContext() {
    this.metadata = new grpc.Metadata();
    this.call = {'metadata': this.metadata};
    this.properties = {
      'serviceFullName': 'a.b.Service',
      'methodFullName': 'a.b.Service.methodName',
      'methodName': 'methodName',
    };
    this.context = {'call': this.call, 'metadata': this.metadata, 'properties': this.properties};
  }

  setupValidContext(token) {
    this.setupEmptyContext();
    this.metadata.add('authorization', token);
  }
};
