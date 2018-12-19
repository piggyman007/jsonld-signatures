/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const strictDocumentLoader = require('./documentLoader');
const strictExpansionMap = require('./expansionMap');

const api = {};
module.exports = api;

/**
 * Signs a JSON-LD document using a LinkedDataSignature suite.
 *
 * @param input {object|string} Object to be signed, either a string URL
 *   (resolved to an object by `jsonld.expand()`) or a plain object (JSON-LD
 *   document).
 * @param options {object} Options hashmap.
 *
 * A `suite` option is required:
 *
 * @param options.suite {LinkedDataSignature} a signature suite instance.
 *
 * Verification key identifier is required:
 *
 * @param options.creator {string} A key id URL to the paired public key.
 *
 * A `purpose` option is required:
 *
 * @param options.purpose {ProofPurpose} a proof purpose instance.
 *
 * Advanced optional parameters and overrides:
 *
 * @param [documentLoader] {function} a custom document loader,
 *   `Promise<RemoteDocument> documentLoader(url)`.
 * @param [expansionMap] {function} A custom expansion map that is
 *   passed to the JSON-LD processor; by default a function that will throw
 *   an error when unmapped properties are detected in the input, use `false`
 *   to turn this off and allow unmapped properties to be dropped or use a
 *   custom function.
 *
 * @return {Promise<object>} resolves with the signed input document, with
 *   the signature in the top-level `proof` property.
 */
api.sign = async function sign(input, {
  suite, purpose, documentLoader, expansionMap} = {}) {
  if(!(suite && purpose)) {
    throw new TypeError(
      '"options.suite" and "options.purpose" must be given.');
  }

  if(!documentLoader) {
    documentLoader = strictDocumentLoader;
  }
  if(expansionMap !== false) {
    expansionMap = strictExpansionMap;
  }

  return suite.sign(input, {purpose, documentLoader, expansionMap});
};
