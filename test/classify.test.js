"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { classifyHeaders } = require("../lib/classify");

function headers(values) {
  return classifyHeaders(values);
}

describe("PHP version classification", () => {
  it("marks supported branches below the fixed release as likely affected", () => {
    for (const version of ["8.2.34", "8.3.35", "8.4.26", "8.5.11"]) {
      const result = headers({ "x-powered-by": `PHP/${version}` });
      assert.equal(result.status, "likely_affected", version);
      assert.equal(result.phpVersion, version);
    }
  });

  it("marks the fixed release and later point releases as likely patched", () => {
    for (const version of ["8.2.35", "8.2.36", "8.3.36", "8.4.27", "8.4.28", "8.5.12", "8.5.13"]) {
      const result = headers({ server: `Apache/2.4.62 (Debian) PHP/${version}` });
      assert.equal(result.status, "likely_patched", version);
    }
  });

  it("marks 8.1 and older as end of life", () => {
    for (const version of ["8.1.29", "8.0.30", "7.4.33", "5.6.40"]) {
      assert.equal(headers({ "x-powered-by": `PHP/${version}` }).status, "eol", version);
    }
  });

  it("keeps a distro suffix on the upstream version it advertises", () => {
    const eol = headers({ server: "Apache/2.4.52 (Ubuntu) PHP/8.1.2-1ubuntu2.22" });
    assert.equal(eol.status, "eol");
    assert.equal(eol.phpVersion, "8.1.2");
    const patched = headers({ "x-powered-by": "PHP/8.2.35-1ubuntu1" });
    assert.equal(patched.status, "likely_patched");
    assert.equal(patched.phpVersion, "8.2.35");
  });

  it("does not treat pre-releases as patched", () => {
    assert.equal(headers({ "x-powered-by": "PHP/8.3.36RC1" }).status, "unknown");
    assert.equal(headers({ "x-powered-by": "PHP/8.2.35-dev" }).status, "unknown");
  });

  it("leaves newer unknown branches unclassified", () => {
    assert.equal(headers({ "x-powered-by": "PHP/8.6.1" }).status, "unknown");
    assert.equal(headers({ "x-powered-by": "PHP/9.0.0" }).status, "unknown");
  });
});

describe("missing PHP versions", () => {
  it("reports WordPress from headers without calling it PHP-free", () => {
    const result = headers({
      link: '<https://example.com/wp-json/>; rel="https://api.w.org/"',
      server: "nginx",
    });
    assert.equal(result.status, "unknown");
    assert.equal(result.wordpress, true);
  });

  it("recognizes pingback and redirect headers as WordPress", () => {
    assert.equal(headers({ "x-pingback": "https://example.com/xmlrpc.php" }).wordpress, true);
    assert.equal(headers({ "x-redirect-by": "WordPress" }).wordpress, true);
  });

  it("uses not_php only for a positive non-PHP stack", () => {
    assert.equal(headers({ "x-powered-by": "Express" }).status, "not_php");
    assert.equal(headers({ server: "Kestrel" }).status, "not_php");
    assert.equal(headers({ server: "nginx" }).status, "unknown");
    assert.equal(headers({ server: "cloudflare" }).status, "unknown");
    assert.equal(headers({ server: "Apache" }).status, "unknown");
  });

  it("prefers a PHP version over a non-PHP token", () => {
    const result = headers({ "x-powered-by": "PHP/8.2.20", server: "Express" });
    assert.equal(result.status, "likely_affected");
  });

  it("does not echo control characters from headers", () => {
    const result = headers({ "x-powered-by": "PHP/8.4.27\r\nSet-Cookie: a=b" });
    assert.equal(result.status, "likely_patched");
    assert.equal(result.xPoweredBy.includes("\n"), false);
    assert.equal(result.xPoweredBy.includes("\r"), false);
  });
});
