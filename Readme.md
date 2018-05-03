# passlib

Storing passwords securely, simplified

## Usage

```js
const passlib = require("passlib");

async function createUser(name, password) {
  const wrapped = await passlib.create(password);
  await db.store(name, wrapped); // or something like that
}

async function checkCredentials(name, password) {
  const expected = await db.get(name); // or something like that

  /* The actual check!
   * Make sure to always call this function (with a dummy password if needed),
   * even if you didn't find an account in your db, unless you're OK with an
   * attacker finding out all valid user names in your system.
   * If you do not call this function, the attacker may try user names and see
   * when something responds real quick, meaning no password check performed,
   * ergo not a valid user, or somewhat slower, account valid as it tried to
   * verify the password.
   * This is not a concern if you user directory is public anyway.
   */
  if (!(await passlib.verify(expected, password))) {
    throw new Error("Incorrect credentials");
  }

  // Upgrade when needed, so we always use the most current version
  if (passlib.needsUpgrade(expected)) {
    const wrapped = await passlib.create(password);
    await db.store(name, wrapped); // or something like that
  }
}
```

## Word of advise

Do not mess with the wrapped values, ever. Just consider them opaque.

## Algorithms

### v1

This algorithm derives a key `k` using
`crypto.pbkdf2(password, salt, iterations, salt, 64, "sha512")`
where `salt` is a per-call generated crypto-random buffer of 32-bytes, and
`iterations` is a value of minimum 20000 but adjusted to take approximately at
least 100 milliseconds on the runtime computer.

A `check = SHA224(VERSION(1) | iterations | salt)` is computed, acting as a
checksum around the parameters.

Finally, using `mac = HMAC-SHA512(k, VERSION(1) | iterations | salt | check)`
(the important bit), the concatenation of
`VERSION(1) | iterations | salt | check | mac` is returned, acting as the
wrapped password value that can be securely stored.

This construction is analog to what scrypt (and node-scrypt) are using, except
for the different KDF of course.
Using PBKDF2 has the drawback that it is better "crackable" than e.g. scrypt.
The decision to use it instead of scrypt in this version stems from PBKDF2
being part of the node standard library. It still is believed to be secure
enough (given enough iterations)<sup>[citation needed]</sup> today.

### v0

*Do **NOT** Use*: The password is just put plain text into a buffer,
aka zero security. This version exists mainly for testing purposes.
Did I mention you should **NOT EVER** use this?
