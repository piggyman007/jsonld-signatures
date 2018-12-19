/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// load locally embedded contexts
const contexts = require('./contexts');

const api = {};
module.exports = api;

api.extendEmbeddedContextLoader = documentLoader => {
  return async url => {
    const context = contexts[url];
    if(context !== undefined) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: context
      };
    }
    return documentLoader(url);
  };
};

api.embeddedContextLoader = api.extendEmbeddedContextLoader(url => {
  throw new Error(`${url} not found.`);
});
