"use strict";

const {ensureBuffer} = require("./util");
const argon2 = require("argon2");

const VERSION = 2;

async function create(password) {
  const hash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 20 * 1024, // in KiB
    timeCost: 5,
    parallelism: 1,
    version: 0x13,
    saltLength: 16,
    hashLength: 32
  });
  const hashBuffer = Buffer.from(hash);
  const rv = Buffer.alloc(2 + hashBuffer.length);
  rv.writeUInt16BE(VERSION, 0);
  hashBuffer.copy(rv, 2);
  return rv;
}

async function verify(buffer, password) {
  ensureBuffer(buffer);
  const v = buffer.readUInt16BE(0);
  if (v !== VERSION) {
    throw new Error("Version mismatch");
  }

  const hash = buffer.slice(2).toString("utf-8");
  return await argon2.verify(hash, password);
}

module.exports = {
  create,
  verify
};
