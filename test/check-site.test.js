"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { CheckError } = require("../lib/errors");
const { checkSite } = require("../lib/check-site");

function deps(responses, pins) {
  const calls = [];
  let index = 0;
  return {
    calls,
    resolvePublicAddress: async (hostname) => {
      if (String(hostname).includes("127.0.0.1") || String(hostname).includes("169.254")) {
        throw new CheckError("blocked");
      }
      return (pins && pins.shift()) || { address: "93.184.216.34", family: 4 };
    },
    requestHeaders: async (target, pin) => {
      calls.push({ href: target.href, method: "GET", pin });
      const next = responses[index++];
      if (!next) throw new CheckError("network");
      if (next instanceof Error) throw next;
      return next;
    },
  };
}

describe("checkSite", () => {
  it("classifies a pinned public response", async () => {
    const fake = deps([{ statusCode: 200, headers: { "x-powered-by": "PHP/8.4.27", server: "Apache" } }]);
    const result = await checkSite("https://example.com/blog", fake);
    assert.equal(result.status, "likely_patched");
    assert.equal(result.finalUrl, "https://example.com/blog");
    assert.equal(fake.calls[0].pin.address, "93.184.216.34");
    assert.equal(fake.calls[0].method, "GET");
  });

  it("follows a redirect only after the next URL is public", async () => {
    const fake = deps([
      { statusCode: 301, headers: { location: "https://www.example.com/", server: "nginx" } },
      { statusCode: 200, headers: { "x-powered-by": "PHP/8.3.36" } },
    ]);
    const result = await checkSite("https://example.com", fake);
    assert.equal(result.status, "likely_patched");
    assert.equal(result.finalUrl, "https://www.example.com/");
    assert.equal(fake.calls.length, 2);
  });

  it("does not request a redirect to a metadata address", async () => {
    const fake = deps([{ statusCode: 302, headers: { location: "http://169.254.169.254/latest/meta-data" } }]);
    await assert.rejects(
      () => checkSite("https://example.com", fake),
      (err) => err instanceof CheckError && err.code === "blocked",
    );
    assert.equal(fake.calls.length, 1);
  });

  it("does not request localhost when the user submits it", async () => {
    let called = false;
    await assert.rejects(
      () =>
        checkSite("http://127.0.0.1/", {
          requestHeaders: async () => {
            called = true;
            return { statusCode: 200, headers: {} };
          },
        }),
      (err) => err instanceof CheckError && err.code === "blocked",
    );
    assert.equal(called, false);
  });

  it("tries HTTPS before an explicit HTTP URL", async () => {
    const fake = deps([
      new CheckError("tls"),
      { statusCode: 200, headers: { "x-powered-by": "PHP/8.2.20" } },
    ]);
    const result = await checkSite("http://example.com/app", fake);
    assert.equal(fake.calls[0].href, "https://example.com/app");
    assert.equal(fake.calls[1].href, "http://example.com/app");
    assert.equal(result.status, "likely_affected");
    assert.match(result.schemeNote, /used HTTP/);
  });

  it("stops after too many redirects", async () => {
    const fake = deps([
      { statusCode: 302, headers: { location: "https://example.com/a" } },
      { statusCode: 302, headers: { location: "https://example.com/b" } },
      { statusCode: 302, headers: { location: "https://example.com/c" } },
    ]);
    await assert.rejects(
      () => checkSite("https://example.com", fake),
      (err) => err instanceof CheckError && err.code === "redirect",
    );
  });
});
