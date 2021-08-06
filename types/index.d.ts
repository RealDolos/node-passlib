/**
 * Current version
 */
export var CURRENT_VERSION: number;

/**
 * Checks whether a stored value needs updating to a new version.
 * Important: this does *NOT* check the integrity of a stored value.
 * @param {string|Buffer} value Value to check
 * @returns {boolean} True if update is needed
 */
export function needsUpgrade(value: string | Buffer): boolean;

export interface Options {
    version?: 0 | 1 | 2;
    asBuffer?: boolean;
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
export function create(password: string, options: Options & {asBuffer?: true}): Promise<Buffer>;
export function create(password: string, options?: Options & {asBuffer?: false}): Promise<string>;

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
export function verify(value: string | Buffer, password: string): Promise<boolean>;
