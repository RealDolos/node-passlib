# passlib

Storing passwords securely, simplified

## Usage

```js
const passlib = require("passlib");

async function createUser(name, password) {
  let wrapped = await passlib.create(password);
  await db.store(name, wrapped); // or something like that
}

async function checkCredentials(name, password) {
  let expected = await db.get(name); // or something like that

  // the actual check
  if (!(await passlib.verify(expected, password))) {
    throw new Error("Incorrect credentials");
  }

  // Upgrade when needed, so we always use the most current version
  if (passlib.needsUpgrade(expected)) {
    password = await passlib.create(password);
    await db.store(name, password); // or something like that
  }
}
```

## Algorithms

### v1

This algorithm derives a key `k` using
`crypto.pbkdf2(password, salt, iterations, salt, 64, "sha512")`
where `salt` is a per-call generated crypto-random buffer of 32-bytes, and
`ìterations` is a value of minimum 20000 but adjusted to take approximately at
least 100 milliseconds on the current computer.

A `check = SHA224(VERSION(1) | iterations | salt)` is computed, acting as a
checksum around the parameters.

Finally, using `mac = HMAC-SHA512(k, VERSION(1) | iterations | salt | check)`
(the important bit), the concatenation of
`VERSION(1) | iterations | salt | check | mac` is returned, acting as the
wrapped password value that can be securely stored.

This construction is analog to what scrypt (and node-script) are using, except
for the different KDF of course.
Using PBKDF2 has the drawback that it is better "crackable" than e.g. scrypt.
The decision to use it instead of scrypt in this version stemas from PBKDF2
being part of the node standard library. It still is believed to be secure
enough (given enough iterations) today.

### v0

*Do **NOT** Use*: The password just just put plaintext into a buffer,
aka zero security. This version exists mainly for testing purposes.
