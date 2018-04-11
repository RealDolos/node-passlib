"use strict";

const crypto = require("crypto");
const {ensureBuffer, pbkdf2, isSameConstantTime} = require("./util");

const VERSION = 1;
const VERSION_LEN = 2;
let iter = 20000;
const ITER_LEN = 4;
const SALT_LEN = 32;
const CHECK = "sha224";
const CHECK_LEN = 28;
const KDF = "sha512";
const KEY_LEN = 64;
const MAC = "sha256";
const MAC_LEN = 32;
const TARGET = 100; // Lower bound time target in ms

const TO_ITER_LEN = VERSION_LEN + ITER_LEN;
const TO_SALT_LEN = TO_ITER_LEN + SALT_LEN;
const TO_CHECK_LEN = TO_SALT_LEN + CHECK_LEN;
const FULL_LEN = TO_CHECK_LEN + MAC_LEN;

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
  const rv = Buffer.alloc(FULL_LEN);
  rv.writeUInt16BE(VERSION, 0);
  rv.writeUInt32BE(iter, VERSION_LEN);
  crypto.randomFillSync(rv, TO_ITER_LEN, SALT_LEN);
  const salt = rv.slice(TO_ITER_LEN, TO_SALT_LEN);

  const check = crypto.createHash(CHECK);
  check.update(rv.slice(0, TO_SALT_LEN));
  check.digest().copy(rv, TO_SALT_LEN);

  const key = await pbkdf2(password, salt, iter, KEY_LEN, KDF);

  const hmac = crypto.createHmac(MAC, key);
  hmac.update(rv.slice(0, TO_CHECK_LEN));
  hmac.digest().copy(rv, TO_CHECK_LEN);

  return rv;
}

async function verify(buffer, password) {
  ensureBuffer(buffer);
  const ver = buffer.readUInt16BE(0);
  if (ver !== VERSION) {
    throw new Error("Version mismatch");
  }
  if (buffer.length !== FULL_LEN) {
    throw new Error("Truncated");
  }

  const iterations = buffer.readUInt32BE(VERSION_LEN);
  const salt = buffer.slice(TO_ITER_LEN, TO_SALT_LEN);
  const expectedCheck = buffer.slice(TO_SALT_LEN, TO_CHECK_LEN);

  const check = crypto.createHash(CHECK);
  check.update(buffer.slice(0, TO_SALT_LEN));
  const actualCheck = check.digest();
  // no need to prevent timing side channels, as an attacker can ensure
  // this check always suceeeds anyway
  if (Buffer.compare(expectedCheck, actualCheck)) {
    return false;
  }

  const expectedMAC = buffer.slice(TO_CHECK_LEN, FULL_LEN);
  const key = await pbkdf2(password, salt, iterations, KEY_LEN, KDF);

  const hmac = crypto.createHmac(MAC, key);
  hmac.update(buffer.slice(0, TO_CHECK_LEN));
  const actualMAC = hmac.digest();

  // potential timing side channel since we compare mac, so use same()
  return isSameConstantTime(expectedMAC, actualMAC);
}

module.exports = {
  init,
  create,
  verify
};
