/*
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('../constants');
const forge = require('node-forge');
const jsonld = require('jsonld');
const util = require('../util');
const Helper = require('../Helper');

// TODO: reorganize this class further and make it more obvious which
// methods need to be extended in proof plugins

// TODO: make signature and verification code (and potentially other code)
// more DRY, especially wrt. plugins having reimplement functionality

module.exports = class LinkedDataSignature {
  /**
   * @param type {string} Provided by subclass.
   *
   * Parameters required to use a suite for signing:
   *
   * @param [creator] {string} A key id URL to the paired public key.
   *
   * Advanced optional parameters and overrides:
   *
   * @param [proof] {object} a JSON-LD document with options to use for
   *   the `proof` node (e.g. any other custom fields can be provided here
   *   using a context different from security-v2).
   * @param [date] {string|Date} signing date to use if not passed.
   * @param [domain] {string} domain to include in the signature.
   * @param [nonce] {string} nonce to include in the signature.
   *
   * TODO: add verify functions like checking date and nonce
   */
  constructor({type, creator, proof, date, domain, nonce}) {
    // validate common options
    if(creator !== undefined && typeof creator !== 'string') {
      throw new TypeError('"creator" must be a URL string.');
    }
    if(domain !== undefined && typeof domain !== 'string') {
      throw new TypeError('"domain" must be a string.');
    }
    if(nonce !== undefined && typeof nonce !== 'string') {
      throw new TypeError('"nonce" must be a string.');
    }

    this.type = type;
    this.creator = creator;
    this.proof = proof;
    this.date = date;
    this.domain = domain;
    this.nonce = nonce;
    this.helper = new Helper();
  }

  async canonize(input, options) {
    const opts = {
      algorithm: 'URDNA2015',
      format: 'application/n-quads',
      documentLoader: options.documentLoader,
      expansionMap: options.expansionMap,
      skipExpansion: options.skipExpansion === true
    };
    return jsonld.canonize(input, opts);
  }

  /**
   * @param input {string|object} Object to be signed, either a string URL
   *   (resolved to an object by `jsonld.expand()`) or a plain object (JSON-LD
   *   doc).
   *
   * @param options {object}
   * @param options.proof {object}
   *
   * @param [options.documentLoader] {function}
   * @param [options.expansionMap]
   *
   * @returns {Promise<{data: *, encoding: string}>}
   */
  async createVerifyData(input, options) {
    // TODO: frame before getting signature, not just compact? considerations:
    // should the assumption be (for this library) that the signature is on
    // the top-level object and thus framing is unnecessary?
    // FIXME: yes, assumption for this lib should be top-level object ONLY
    const opts = {
      documentLoader: options.documentLoader,
      expansionMap: options.expansionMap
    };
    const [expanded = {}] = await jsonld.expand(input, opts);

    // TODO: will need to preserve `proof` when chained signature
    // option is used and implemented in the future

    // delete the existing proofs(s) prior to canonicalization
    delete expanded[constants.SECURITY_PROOF_URL];

    // ensure signature values are removed from proof node
    const proof = await this.sanitizeProofNode(options.proof, options);

    // concatenate hash of c14n proof options and hash of c14n document
    const c14nProofOptions = await this.canonize(proof, options);
    const canonizeOptions = {...options, skipExpansion: true};
    const c14nDocument = await this.canonize(expanded, canonizeOptions);
    return {
      data: this._sha256(c14nProofOptions).getBytes() +
        this._sha256(c14nDocument).getBytes(),
      encoding: 'binary'
    };
  }

  async sanitizeProofNode(proof, options) {
    // `jws`,`signatureValue`,`proofValue` must not be included in the proof
    // options
    proof = util.deepClone(proof);
    delete proof.jws;
    delete proof.signatureValue;
    delete proof.proofValue;
    return proof;
  }

  /**
   * @param input {string|object} Object to be signed, either a string URL
   *   (resolved to an object by `jsonld.expand()`) or a plain object (JSON-LD
   *   document).
   *
   * @returns {Promise<object>} Resolves with the signed input document, with
   *   the signature in the top-level `proof` property.
   */
  async sign(input, {purpose, documentLoader, expansionMap}) {
    // build proof (currently known as `signature options` in spec)
    let proof;
    if(this.proof) {
      // use proof JSON-LD document passed to API
      const options = {documentLoader, expansionMap};
      proof = await jsonld.compact(
        this.proof, constants.SECURITY_CONTEXT_URL, options);
    } else {
      // create proof JSON-LD document
      proof = {'@context': constants.SECURITY_CONTEXT_URL};
    }

    // ensure proof type is set
    proof.type = this.type;

    // set default `now` date if not given in `proof` or `options`
    let date = this.date;
    if(proof.created === undefined && date === undefined) {
      date = new Date();
    }

    // ensure date is in string format
    if(date !== undefined && typeof date !== 'string') {
      date = util.w3cDate(date);
    }

    // add API overrides
    if(date !== undefined) {
      proof.created = date;
    }
    if(this.creator !== undefined) {
      proof.creator = this.creator;
    }
    if(this.domain !== undefined) {
      proof.domain = this.domain;
    }
    if(this.nonce !== undefined) {
      proof.nonce = this.nonce;
    }

    // add fields from proofPurpose
    // the proof going into the handler is compacted in the SECURITY_CONTEXT
    // and the handler *must* maintain this form. Handlers that introduce terms
    // that are not in the SECURITY_CONTEXT *must* compact the proof using the
    // SECURITY_CONTEXT before returning
    purpose.updateProof({
      // TODO:

    })

    const {proofPurposeHandler, purposeParameters = {}} = options;
    if(proofPurposeHandler) {
      if(!(purposeParameters && typeof purposeParameters === 'object')) {
        throw new TypeError('"options.purposeParameters" must be an object.');
      }
      proof = await proofPurposeHandler.createProof({
        input, proof, purposeParameters,
        documentLoader: options.documentLoader});
    }

    // produce data to sign
    options.proof = proof;
    const verifyData = await this.createVerifyData(input, options);
    // create proof node
    const proofNode = await this.createProofNode(verifyData, options);
    // attach proof node
    return this.attachProofNode(input, proofNode, options);
  }

  async createProofNode(verifyData, options) {
    const proof = options.proof;
    proof.jws = await this.createSignatureValue(verifyData, options);
    return proof;
  }

  async attachProofNode(input, proofNode, options) {
    // compact proof node to match input context
    const tmp = {
      'https://w3id.org/security#proof': {
        '@graph': proofNode
      }
    };
    const ctx = jsonld.getValues(input, '@context');
    const opts = {expansionMap: options.expansionMap};
    if(options.documentLoader) {
      opts.documentLoader = options.documentLoader;
    }
    const compactProofNode = await jsonld.compact(tmp, ctx, opts);

    // TODO: it is unclear how the signature would be easily added without
    // reshaping the input... so perhaps this library should just require
    // the caller to accept that the signature will be added to the top
    // level of the input

    // attach signature node to cloned input and return it
    const output = util.deepClone(input);
    delete compactProofNode['@context'];
    const proofKey = Object.keys(compactProofNode)[0];
    jsonld.addValue(output, proofKey, compactProofNode[proofKey]);
    return output;
  }

  async verify(framed, options) {
    options = {...options};

    const proof = framed.signature || framed.proof;
    proof['@context'] = framed['@context'];

    const maxTimestampDelta = (15 * 60);
    // destructure options
    let {
      checkNonce = () => (
        proof.nonce === null || proof.nonce === undefined),
      checkDomain = () => (
        proof.domain === null || proof.domain === undefined),
      checkTimestamp = () => {
        const now = Date.now();
        const delta = maxTimestampDelta * 1000;
        const created = Date.parse(proof.created);
        if(created < (now - delta) || created > (now + delta)) {
          throw new Error('The digital signature timestamp is out of range.');
        }
        return true;
      },
      checkKey = this.helper.checkKey.bind(this.helper),
      publicKey: getPublicKey = this.helper.getPublicKey.bind(this.helper)
    } = options;

    // normalize function options
    if(checkNonce === false) {
      // not checking nonce, so return true
      checkNonce = () => true;
    }
    if(checkDomain === false) {
      // not checking domain, so return true
      checkDomain = () => true;
    }
    if(checkTimestamp === false) {
      // not checking timestamp, so return true
      checkTimestamp = () => true;
    }
    if(typeof getPublicKey !== 'function') {
      const key = getPublicKey;
      getPublicKey = keyId => {
        if(keyId !== key.id) {
          throw new Error('Public key not found.');
        }
        return key;
      };
    }
    checkNonce = util.normalizeAsyncFn(checkNonce, 2);
    checkDomain = util.normalizeAsyncFn(checkDomain, 2);
    checkTimestamp = util.normalizeAsyncFn(checkTimestamp, 2);
    checkKey = util.normalizeAsyncFn(checkKey, 2);
    getPublicKey = util.normalizeAsyncFn(getPublicKey, 2);
    // run nonce, domain, and timestamp checks in parallel
    const checks = await Promise.all([
      checkNonce(proof.nonce, options),
      checkDomain(proof.domain, options),
      checkTimestamp(proof.date, options)
    ]);

    if(!checks[0]) {
      throw new Error('The nonce is invalid.');
    }
    if(!checks[1]) {
      throw new Error('The domain is invalid.');
    }
    if(!checks[2]) {
      throw new Error('The timestamp is invalid.');
    }
    const keyOptions = {
      ...options,
      proof,
      keyType: this.requiredKeyType
    };
    // get public key
    const publicKey = await getPublicKey(proof.creator, keyOptions);
    // TODO: should be able to override revocation check to ensure that
    // signatures made prior to the revocation check could potentially still
    // be verified

    // ensure key is not revoked
    if(publicKey.revoked !== undefined) {
      throw new Error(
        'The document was signed with a key that has been revoked.');
    }

    // validate key
    await this.validateKey(publicKey, keyOptions);
    // verify input
    const verifyData = await this.createVerifyData(
      framed, {
        ...options,
        date: proof.created,
        nonce: proof.nonce,
        domain: proof.domain,
        proof
      });

    // verify proof node (i.e. check signature)
    const verified = await this.verifyProofNode(
      verifyData, proof,
      {...options, publicKey});
    if(!verified) {
      return false;
    }

    // ensure key is trusted before proceeding
    const isKeyTrusted = await checkKey(publicKey, keyOptions);
    if(!isKeyTrusted) {
      throw new Error('The document was not signed with a trusted key.');
    }

    // Check that the proofPurpose is valid
    const {purpose} = options;
    if(purpose) {
      const {proofPurposeHandler, purposeParameters, documentLoader} = options;
      const {valid, error} = await proofPurposeHandler.validate({
        document: framed,
        proof,
        purposeParameters: {
          ...purposeParameters,
          // include `publicKey` and `keyOptions` for any signature purpose
          publicKey,
          keyOptions
        },
        documentLoader
      });
      if(!valid) {
        throw error;
      }
    }

    return true;
  }

  async verifyProofNode(verifyData, proof, options) {
    throw new Error(
      '"verifyProofNode" must be implemented in a derived class.');
  }

  // TODO: use node `crypto` and Buffers in node environment
  // returns a forge buffer
  _sha256(str, encoding) {
    // browser or other environment
    const md = forge.md.sha256.create();
    md.update(str, encoding || 'utf8');
    return md.digest();
  }
};
