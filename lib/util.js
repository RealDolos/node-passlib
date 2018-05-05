"use strict";

const crypto = require("crypto");
const {promisify} = require("util");

const pbkdf2 = promisify(crypto.pbkdf2);


function ensureBuffer(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error("Must provide a buffer");
  }
}

/**
 * Check if two buffers are the same, in (hopefully) near constant-time
 *
 * @param {Buffer} a first buffer
 * @param {Buffer} b second buffer
 * @returns {boolean} True if buffers are the same
 */
function isSameConstantTime(a, b) {
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


module.exports = {
  ensureBuffer,
  pbkdf2,
  isSameConstantTime,
};
