'use strict';

const dns = require('dns');
const Pool = require('concurrent-request');
const crypto = require('crypto');
const base64url = require('base64url');

const DEFAULTS = {
  tldService: 'dns.storj.farm',
  domain: 'storj.farm',
  requestInterval: count => Math.pow(2, count) * 1000,
  requestJitter: 0,
  requestPoolSize: 1,
  requestRetryCount: 10,
  requestHandler: (e, resp, body, cb) => {
    if (e) { return cb(e); }
    if (resp.statusCode === 400 || resp.statusCode === 401) {
      // Don't retry on malformed requests
      return cb();
    }
    if (resp.statusCode !== 200) { return cb(new Error(body.error)); }
    return cb();
  },
};

const m = function StorjShareLE(opts, cb) {
  const self = this;
  if (!(this instanceof StorjShareLE)) {
    return new StorjShareLE(opts, cb);
  }
  self.config = Object.assign({}, DEFAULTS, opts);
  // We require a key
  self.key = opts.key;
  if (!self.key
    || typeof self.key.sign !== 'function'
    || typeof self.key.getNodeID !== 'function'
    || typeof self.key.getPublicKey !== 'function') {
    throw new Error('Require valid key for generating a cert');
  }
  self.subdomain = self.key.getNodeID();
  self.request = new Pool({
    interval: self.config.requestInterval,
    jitter: self.config.requestJitter,
    size: self.config.requestPoolSize,
    tries: self.config.requestRetryCount,
    handler: self.config.requestHandler,
  });
  self.request({
    url: self.config.tldService,
    method: 'POST',
    json: true,
    body: {
      type: 'A',
      value: self.config.ip,
      key: self.key.getPublicKey(),
      signature: self.key.sign(self.config.ip),
    },
  }, (e, req, body) => {
    if (e) { return cb(e); }
    if (body.error) { return cb(new Error(body.error)); }
    if (self.subdomain !== body.nodeID) {
      return cb(new Error('invalid key'));
    }
    self.nodeID = body.nodeID;
    // We know the record will exist eventually, for now go ahead and do the LE
    // handshake, we can wait for both the A and TXT records to propogate at
    // the same time.
    return cb();
  });

  return this;
};

m.prototype.verifyRecord = function verifyRecord(name, type, value, a, cb) {
  const self = this;
  if (typeof a === 'function') {
    return self.verifyRecord(name, type, value, 0, a);
  }
  // attempt lets us wait for the DNS value to stabalize before calling out to
  // letsencrypt for validation
  let attempt = a;

  // Wait for DNS to update, makes sure LE can actually see the value in the
  // handshake.
  return dns.resolve(`${name}.${self.config.domain}`, type, (e, records) => {
    attempt += 1;
    // Keep retrying until it resolves to the proper value
    if (e || (type === 'A' ? records[0] : records[0][0]) !== value) {
      attempt = 0; // restart
      // Try again in 1 second
    }

    // Make sure we see the value consistently for 60 seconds before we ask LE
    // to take a peek
    if (attempt < 60) {
      return setTimeout(
        // eslint-disable-next-line comma-dangle
        verifyRecord.bind(self), 1000, name, type, value, attempt, cb
      );
    }
    return cb();
  });
};

m.prototype.set = function set(opts, domain, key, value, cb) {
  const self = this;
  // Some arbitrary transformation that LE requires for DNS TXT values
  const digest =
    base64url(crypto.createHash('sha256').update(value || '').digest());
  self.request({
    url: self.config.tldService,
    method: 'POST',
    json: true,
    body: {
      type: 'TXT',
      value: digest,
      key: self.key.getPublicKey(),
      signature: self.key.sign(digest),
    },
  }, (e, req, body) => {
    if (e) { return cb(e); }
    if (body.error) { return cb(new Error(body.error)); }
    // We can provide a valid signature, but the key can belong to the wrong
    // nodeID, which is still an error condition.
    if (body.nodeID !== self.nodeID) {
      return cb(new Error('Invalid key'));
    }
    // Wait for the TXT record to propogate
    const name = `_acme-challenge.${self.nodeID}`;
    return self.verifyRecord(name, 'TXT', digest, () =>
      // Wait for the A record to finish propogating
      // eslint-disable-next-line comma-dangle
      self.verifyRecord(self.nodeID, 'A', self.config.ip, cb)
    );
  });
};

m.prototype.get = function get(defaults, domain, key, done) {
  const name = `${this.subdomain}.${this.domain}`;
  return dns.resolve(name, 'TXT', (e, records) => {
    let record = undefined; // eslint-disable-line no-undef-init
    if (records instanceof Array) {
      record = records[0];
    }
    return done(e, record);
  });
};

m.prototype.remove = function remove(defaults, domain, key, done) {
  return done(new Error('Not implemented'));
};

m.prototype.getOptions = function getOptions() {
  return this.config;
};

m.prototype.loopback = m.prototype.get;

module.exports = m;
