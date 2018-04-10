"use strict";

const v0 = require("./v0");
const v1 = require("./v1");

const VERSIONS = Object.freeze(new Map([
  [0, v0],
  [1, v1]
]));
const INITIALIZED = new Map();

const CURRENT_VERSION = 1;

/**
 * Checks whether a stored value needs updating to a new version
 * @param {string} value Value to check
 * @returns {boolean} True if update is needed
 */
function needsUpgrade(value) {
  try {
    if (!Buffer.isBuffer(value)) {
      value = Buffer.from(value, "base64");
    }
    const v = value.readUInt16BE(0);
    return v !== CURRENT_VERSION;
  }
  catch (ex) {
    return true;
  }
}

async function lookup(version) {
  let impl = INITIALIZED.get(version);
  if (impl) {
    return impl;
  }
  impl = VERSIONS.get(version);
  if (!impl) {
    throw new Error("Unknown version");
  }
  if (!impl.init) {
    if (version === 0) {
      console.warn("passlib v0 offering zero security used!");
    }
    INITIALIZED.set(version, impl);
    return impl;
  }
  if (!impl.pending) {
    impl.pending = impl.init();
  }
  await impl.pending;
  INITIALIZED.set(version, impl);
  return impl;
}

/**
 * Creates a value from a password that is suitable for storing
 * in a peristent store. If the store ever gets compromised,
 * the returned value is supposed to be secure enough so that
 * the password cannot be computed from it.
 *
 * @async
 * @param {string} password Password to wrap
 * @param {integer} [version] Create with this specific version
 *   instead of the most current one
 * @returns {Promise<string>} Wrapped password value
 */
async function create(password, version) {
  const vt = typeof version;
  if (vt !== "number" && vt !== "undefined") {
    throw new Error("Invalid version type");
  }
  version = isFinite(version) ? version : CURRENT_VERSION;
  const impl = await lookup(version);
  const rv = await impl.create(password);
  return rv.toString("base64");
}

/**
 * Verifies a stored value created by this library matches
 * a user provided password.
 *
 * @async
 * @param {string} value Previously stored value
 * @param {string} password Password to wrap
 * @returns {Promise<boolean>} True if password matches
 *   (e.g. login can proceed)
 */
async function verify(value, password) {
  if (!Buffer.isBuffer(value)) {
    value = Buffer.from(value, "base64");
  }
  const version = value.readUInt16BE(0);
  const impl = await lookup(version);
  return impl.verify(value, password);
}

module.exports = {
  needsUpgrade,
  create,
  verify,
};
Object.defineProperty(module.exports, "CURRENT_VERSION", {
  enumerable: true,
  value: CURRENT_VERSION
});
