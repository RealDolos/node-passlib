"use strict";

const {ensureBuffer} = require("./util");

const VERSION = 0;

function create(password) {
  password = Buffer.from(password);
  const rv = Buffer.alloc(2 + password.length);
  password.copy(rv, 2);
  return rv;
}

function verify(buffer, password) {
  ensureBuffer(buffer);
  const v = buffer.readUInt16BE(0);
  if (v !== VERSION) {
    throw new Error("Version mismatch");
  }
  password = Buffer.from(password);
  return Buffer.compare(password, buffer.slice(2)) === 0;
}

module.exports = {
  create,
  verify
};
