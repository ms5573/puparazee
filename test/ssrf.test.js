"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { CheckError } = require("../lib/errors");
const { isBlockedIp, normalizePublicUrl, resolvePublicAddress } = require("../lib/ssrf");

function blocked(ip) {
  assert.equal(isBlockedIp(ip), true, ip);
}

function allowed(ip) {
  assert.equal(isBlockedIp(ip), false, ip);
}

describe("IP blocklist", () => {
  it("blocks private, loopback, link-local, metadata, and reserved ranges", () => {
    for (const ip of [
      "0.0.0.0",
      "10.1.2.3",
      "100.64.0.1",
      "100.100.100.200",
      "100.127.255.255",
      "127.0.0.1",
      "169.254.169.254",
      "172.16.0.1",
      "172.31.255.255",
      "192.0.0.8",
      "192.0.2.1",
      "192.168.1.1",
      "198.18.0.1",
      "198.51.100.5",
      "203.0.113.5",
      "224.0.0.1",
      "240.0.0.1",
      "255.255.255.255",
      "::",
      "::1",
      "fd00:ec2::254",
      "fc00::1",
      "fe80::1",
      "fec0::1",
      "ff02::1",
      "2001:db8::1",
      "::ffff:127.0.0.1",
      "::ffff:7f00:1",
      "::ffff:a00:1",
      "::ffff:a9fe:a9fe",
      "::ffff:ac10:1",
      "::ffff:c0a8:1",
    ]) {
      blocked(ip);
    }
  });

  it("allows ordinary public addresses", () => {
    for (const ip of ["1.1.1.1", "8.8.8.8", "9.9.9.9", "93.184.216.34", "172.15.5.5", "11.0.0.1", "100.128.0.1", "2001:4860:4860::8888", "::ffff:8.8.8.8", "::ffff:808:808"]) {
      allowed(ip);
    }
  });
});

describe("URL normalization", () => {
  it("defaults a bare host to https and keeps the path", () => {
    const url = normalizePublicUrl("example.com/docs?x=1");
    assert.equal(url.href, "https://example.com/docs?x=1");
  });

  it("strips a trailing dot", () => {
    assert.equal(normalizePublicUrl("https://example.com./").href, "https://example.com/");
  });

  it("rejects credentials, other schemes, odd ports, and non-public hosts", () => {
    const samples = [
      "http://user:pass@example.com/",
      "file:///etc/passwd",
      "ftp://example.com/",
      "http://example.com:8080/",
      "https://example.com:8443/",
      "http://127.0.0.1/",
      "http://2130706433/",
      "http://0x7f000001/",
      "http://0177.0.0.1/",
      "http://0/",
      "http://[::1]/",
      "http://[::ffff:127.0.0.1]/",
      "http://169.254.169.254/latest/meta-data",
      "http://localhost/",
      "http://foo.local/",
      "http://metadata.google.internal/",
      "http://printer.internal/",
      "http://example.com\\path",
      "",
      "   ",
      `https://${"a".repeat(2100)}.com/`,
    ];
    for (const sample of samples) {
      assert.throws(() => normalizePublicUrl(sample), (err) => err instanceof CheckError, sample);
    }
  });
});

describe("DNS pinning checks", () => {
  it("rejects a name when any answer is private", async () => {
    await assert.rejects(
      () =>
        resolvePublicAddress("example.com", async () => [
          { address: "93.184.216.34", family: 4 },
          { address: "127.0.0.1", family: 4 },
        ]),
      (err) => err instanceof CheckError && err.code === "blocked",
    );
  });

  it("returns the first public answer without contacting DNS", async () => {
    const pin = await resolvePublicAddress("example.com", async () => [{ address: "93.184.216.34", family: 4 }]);
    assert.deepEqual(pin, { address: "93.184.216.34", family: 4 });
  });

  it("does not look up an IP literal", async () => {
    let called = false;
    const pin = await resolvePublicAddress("8.8.8.8", async () => {
      called = true;
      return [];
    });
    assert.equal(called, false);
    assert.deepEqual(pin, { address: "8.8.8.8", family: 4 });
  });
});
