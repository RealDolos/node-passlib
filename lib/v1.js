"use strict";

const crypto = require("crypto");
const {ensureBuffer, pbkdf2, same} = require("./util");

const VERSION = 1;
let iter = 20000;
const SALT_LEN = 32;
const CHECK = "sha224";
const CHECK_LEN = 28;
const KDF = "sha512";
const KEY_LEN = 64;
const MAC = "sha256";
const MAC_LEN = 32;
const TARGET = 100; // Lower bound time target in ms

async function bench() {
  const pw = "a".repeat(1 << 20);
  const start = Date.now();
  await create(pw);
  return Date.now() - start;
}

async function init() {
  for (let i = 0; i < 3; ++i) {
    const dur = await bench();
    iter = Math.max(iter, Math.floor(iter * (TARGET / dur) / 1000) * 1000);
  }
}


async function create(password) {
  const rv = Buffer.alloc(6 + SALT_LEN + CHECK_LEN + MAC_LEN);
  rv.writeUInt16BE(VERSION, 0);
  rv.writeUInt32BE(iter, 2);
  crypto.randomFillSync(rv, 6, SALT_LEN);
  const salt = rv.slice(6, 6 + SALT_LEN);

  const check = crypto.createHash(CHECK);
  check.update(rv.slice(0, 6 + SALT_LEN));
  check.digest().copy(rv, 6 + SALT_LEN);

  const key = await pbkdf2(password, salt, iter, KEY_LEN, KDF);

  const hmac = crypto.createHmac(MAC, key);
  hmac.update(rv.slice(0, 6 + SALT_LEN + CHECK_LEN));
  hmac.digest().copy(rv, 6 + SALT_LEN + CHECK_LEN);

  return rv;
}

async function verify(buffer, password) {
  ensureBuffer(buffer);
  const v = buffer.readUInt16BE(0);
  if (v !== VERSION) {
    throw new Error("Version mismatch");
  }
  if (buffer.length !== 6 + SALT_LEN + CHECK_LEN + MAC_LEN) {
    throw new Error("Truncated");
  }

  const iterations = buffer.readUInt32BE(2);
  const salt = buffer.slice(6, 6 + SALT_LEN);
  const echeck = buffer.slice(6 + SALT_LEN, 6 + SALT_LEN + CHECK_LEN);

  const check = crypto.createHash(CHECK);
  check.update(buffer.slice(0, 6 + SALT_LEN));
  const acheck = check.digest();
  // no need to prevent timing side channels, as an attacker can ensure
  // this check always suceeeds
  if (Buffer.compare(acheck, echeck)) {
    return false;
  }

  const emac = buffer.slice(
    6 + SALT_LEN + CHECK_LEN,
    6 + SALT_LEN + CHECK_LEN + MAC_LEN);
  const key = await pbkdf2(password, salt, iterations, KEY_LEN, KDF);

  const hmac = crypto.createHmac(MAC, key);
  hmac.update(buffer.slice(0, 6 + SALT_LEN + CHECK_LEN));
  const amac = hmac.digest();

  // timing side channel: since we compare mac
  return same(amac, emac);
}

module.exports = {
  init,
  create,
  verify
};
