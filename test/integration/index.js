'use strict';

const test = require('tape');
const Storj = require('storj');
const StorjShareLE = require('../../index.js');
const LE = require('greenlock');
const LEStore = require('le-store-certbot');
const path = require('path');
const rimraf = require('rimraf');
const mkdirp = require('mkdirp');

const tmpdir = path.join(__dirname, 'tmpdir');

test('create tmpdir', (t) => {
  mkdirp(tmpdir, (e) => {
    t.error(e, 'created dir');
    if (e) { throw e; }
    return t.end();
  });
});

test('Register cert', (t) => {
  t.comment('this test may take a while, it relies on DNS propagation');
  t.comment('you will see a warning about tls-sni, this is normal');
  const storj = new Storj();
  const key = storj.generateKeyPair();
  const config = {
    tldService: process.env.TLD_SERVICE,
    domain: process.env.TLD,
    ip: '127.0.0.1',
    key,
  };
  const store = LEStore.create({
    configDir: path.join(__dirname, 'tmpdir'),
  });
  const leDNS = new StorjShareLE(config, (e) => {
    t.error(e, 'constructor succeeded');
    if (e) { return t.end(); }
    const le = LE.create({
      server: LE.stagingServerUrl,
      store,
      challenges: {
        'dns-01': leDNS,
      },
      challengeType: 'dns-01',
    });
    return le.register({
      domains: [`${key.getNodeID()}.${leDNS.config.domain}`],
      email: 'william.jblankenship@gmail.com',
      agreeTos: true,
      rsaKeySize: 2048,
      challengeType: 'dns-01',
    }).then((results) => {
      t.ok(results, 'creates cert');
      return t.end();
    }, (e2) => {
      t.error(e2, 'doesnt fail');
      return t.end();
    });
  });
});

test('delete tmpdir', (t) => {
  rimraf(tmpdir, (e) => {
    t.error(e, 'created dir');
    if (e) { throw e; }
    return t.end();
  });
});
