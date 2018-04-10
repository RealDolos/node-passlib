"use strict";

const crypto = require("crypto");
const {promisify} = require("util");

function ensureBuffer(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error("Must provide a buffer");
  }
}

/**
 * Check if two buffers are the same, (hopefully) near constant-time
 *
 * @param {Buffer} a first buffer
 * @param {Buffer} b second buffer
 * @returns {boolena} True if buffers are the same
 */
function same(a, b) {
  const len = a.length;
  if (len !== b.length) {
    return false;
  }
  let res = 0;
  for (let i = 0; i < len; ++i) {
    res |= a[i] ^ b[i];
  }
  return !res;
}

const pbkdf2 = promisify(crypto.pbkdf2);

module.exports = {
  ensureBuffer,
  pbkdf2,
  same,
};