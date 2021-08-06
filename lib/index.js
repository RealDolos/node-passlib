"use strict";

const VERSIONS = Object.freeze(new Map([
  [0, require("./v0")],
  [1, require("./v1")],
  [2, require("./v2")],
]));
const INITIALIZED = new Map();

const CURRENT_VERSION = 2;

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

function translateVersion(version) {
  const vt = typeof version;
  const hasVersionNumber = vt === "number";
  if (!hasVersionNumber && vt !== "undefined") {
    throw new Error("Invalid version type");
  }
  if (hasVersionNumber && !isFinite(version)) {
    throw new Error("Invalid version type");
  }
  return hasVersionNumber ?
    version :
    CURRENT_VERSION;
}

/**
 * Checks whether a stored value needs updating to a new version.
 * Important: this does *NOT* check the integrity of a stored value.
 * @param {string|Buffer} value Value to check
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

/**
 * Creates a value from a password that is suitable for storing
 * in a peristent store. If the store ever gets compromised,
 * the returned value is supposed to be secure enough so that
 * the password cannot be computed from it.
 *
 * @async
 * @param {string} password Password to wrap
 * @param {object} [options]
 * @param {integer} [options.version] Create with this specific version
 *   instead of the most current one
 * @param {boolean} [options.asBuffer] Return a node buffer instead of a string
 * @returns {Promise<string|Buffer>} Wrapped password value
 */
async function create(password, options) {
  if (typeof options === "number") {
    // legacy version only call
    options = {version: options};
  }
  options = options || {};
  if (typeof options !== "object") {
    throw new Error("Invalid options");
  }
  const impl = await lookup(translateVersion(options.version));
  const rv = await impl.create(password);
  return options.asBuffer ? rv : rv.toString("base64");
}

/**
 * Verifies a stored value created by this library matches
 * a user provided password.
 *
 * @async
 * @param {string|Buffer} value Previously stored value
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
