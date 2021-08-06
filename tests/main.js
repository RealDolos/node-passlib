"use strict";

const should = require("should"); // eslint-disable-line
const passlib = require("../index");

function createAndVerify(version, desc, str) {
  it(`create and verify (${desc}) v${isFinite(version) ? version : "current"}`, async function() {
    this.slow(900);
    const res = await passlib.create(str, version);
    should(res).be.a.String();
    const same = await passlib.verify(res, str);
    should(same).be.a.Boolean().which.is.true();
    const nu = isFinite(version) ? version !== passlib.CURRENT_VERSION : false;
    should(passlib.needsUpgrade(res)).be.a.Boolean().which.is.exactly(nu);
  });
  it(`create and verify asBuffer (${desc}) v${isFinite(version) ? version : "current"}`, async function() {
    this.slow(900);
    const res = await passlib.create(str, {version, asBuffer: true});
    should(res).be.instanceof(Buffer);
    const same = await passlib.verify(res, str);
    should(same).be.a.Boolean().which.is.true();
    const nu = isFinite(version) ? version !== passlib.CURRENT_VERSION : false;
    should(passlib.needsUpgrade(res)).be.a.Boolean().which.is.exactly(nu);
  });
  it(`create and not verify (${desc}) v${isFinite(version) ? version : "current"}`, async function() {
    this.slow(2000);
    const res = await passlib.create(str, version);
    should(res).be.a.String();
    const same = await passlib.verify(res, `0${str}`);
    should(same).be.a.Boolean().which.is.false();
  });
}

function basic(version) {
  createAndVerify(version, "empty", "");
  createAndVerify(version, "standard", "quertypassword1");
  createAndVerify(version, "standard2", "hunter2");
  createAndVerify(version, "unicode", "hällÖ čœde עִבְרִית 한글");
  createAndVerify(version, "long", "aä".repeat(10 << 20));
}

describe("passlib", function() {
  describe("basic", function() {
    it("has CURRENT_VERSION", function() {
      passlib.should.have.property("CURRENT_VERSION").which.is.a.Number();
      passlib.should.have.property("CURRENT_VERSION").which.is.exactly(2);
    });
    for (let version = 0; version <= passlib.CURRENT_VERSION; ++version) {
      basic(version);
    }
    basic();
  });

  describe("failures", function() {
    const b64 = Buffer.from([0, 1]).toString("base64");
    it("missing param create", function() {
      return passlib.create().should.be.rejectedWith(Error);
    });
    it("invalid version", function() {
      return passlib.create("", "v").should.be.rejectedWith(Error);
    });
    it("unsupported version", function() {
      return passlib.create("", -1).should.be.rejectedWith(Error);
    });
    it("unsupported version 2", function() {
      return passlib.create("", passlib.CURRENT_VERSION + 1).
        should.be.rejectedWith(Error);
    });
    it("missing param verify", function() {
      return passlib.verify().should.be.rejectedWith(Error);
    });
    it("missing param verify 2", function() {
      return passlib.verify(b64).should.be.rejectedWith(Error);
    });
    it("missing param verify 3", function() {
      return passlib.verify(b64, "pw").should.be.rejectedWith(Error);
    });
    it("v1, low iter", async function() {
      this.slow(1000);
      const rv = Buffer.from(await passlib.create("pw", 1), "base64");
      rv.writeUInt32BE(1000, 2);
      return passlib.verify(rv, "pw").should.be.rejectedWith(Error);
    });
    it("v1, high iter", async function() {
      this.slow(1000);
      const rv = Buffer.from(await passlib.create("pw", 1), "base64");
      rv.writeUInt32BE(Math.pow(2, 32) - 1, 2);
      return passlib.verify(rv, "pw").should.be.rejectedWith(Error);
    });
  });
});
