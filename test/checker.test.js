"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { classifyVersion, buildVerdict, detectWordpress } = require("../lib/classify");
const { checkSite } = require("../lib/check-site");
const { isBlockedIp, normalizeInput } = require("../lib/ssrf");
const { SsrfError } = require("../lib/ssrf");
const { fetchHeaders, requestOnce, UA } = require("../lib/http-probe");
const http = require("node:http");

describe("classifyVersion", () => {
  it("matches the fixed releases from check.php", () => {
    assert.equal(classifyVersion("8.5.11"), "vulnerable");
    assert.equal(classifyVersion("8.5.12"), "patched");
    assert.equal(classifyVersion("8.4.26"), "vulnerable");
    assert.equal(classifyVersion("8.4.27"), "patched");
    assert.equal(classifyVersion("8.3.35"), "vulnerable");
    assert.equal(classifyVersion("8.3.36"), "patched");
    assert.equal(classifyVersion("8.2.34"), "vulnerable");
    assert.equal(classifyVersion("8.2.35"), "patched");
    assert.equal(classifyVersion("8.2.35-1ubuntu1"), "patched");
    assert.equal(classifyVersion("8.3"), "vulnerable");
  });

  it("marks the published end-of-life branches and leaves unknown branches alone", () => {
    for (const version of ["8.1.29", "8.0.30", "7.4.33", "5.6.40", "8.1.2-1ubuntu2.22"]) {
      assert.equal(classifyVersion(version), "eol", version);
    }
    assert.equal(classifyVersion("8.6.1"), null);
    assert.equal(classifyVersion("5.1.0"), null);
    assert.equal(classifyVersion("8.3.36RC1"), null);
  });
});

describe("verdicts", () => {
  it("classifies a vulnerable banner and names the fixed release", () => {
    const result = buildVerdict({
      host: "ten-percent.co.uk",
      finalUrl: "https://ten-percent.co.uk/",
      httpCode: 200,
      headers: { server: ["Apache"], "x-powered-by": ["PHP/8.3.35"] },
      wordpress: detectWordpress({}, ""),
    });
    assert.equal(result.verdict, "vulnerable");
    assert.equal(result.php_version, "8.3.35");
    assert.match(result.message, /Update to 8\.3\.36/);
    assert.equal(result.wordpress.is_wp, false);
  });

  it("keeps WordPress evidence from headers and from the wp-json snippet", () => {
    const fromHeader = detectWordpress({ "x-powered-by": ["WordPress"] }, "");
    assert.equal(fromHeader.is_wp, true);
    assert.match(fromHeader.evidence, /X-Powered-By/);
    const fromBody = detectWordpress({}, '{"namespaces":["wp/v2"]}');
    assert.equal(fromBody.evidence, "/wp-json/ REST API present");
  });

  it("uses unknown_wp, unknown, not_php, eol, and unknown_version the way check.php does", () => {
    const wp = buildVerdict({
      host: "example.com",
      httpCode: 200,
      headers: { server: ["nginx"] },
      wordpress: { is_wp: true, evidence: "/wp-json/ REST API present", wp_version: null },
    });
    assert.equal(wp.verdict, "unknown_wp");

    const nginx = buildVerdict({
      host: "example.com",
      httpCode: 200,
      headers: { server: ["nginx"] },
      wordpress: { is_wp: false, evidence: null, wp_version: null },
    });
    assert.equal(nginx.verdict, "unknown");

    const lite = buildVerdict({
      host: "example.com",
      httpCode: 200,
      headers: { server: ["LiteSpeed"] },
      wordpress: { is_wp: false, evidence: null, wp_version: null },
    });
    assert.equal(lite.verdict, "unknown");

    const cdn = buildVerdict({
      host: "example.com",
      httpCode: 200,
      headers: { server: ["cloudflare"] },
      wordpress: { is_wp: false, evidence: null, wp_version: null },
    });
    assert.equal(cdn.verdict, "not_php");

    const eol = buildVerdict({
      host: "example.com",
      httpCode: 200,
      headers: { "x-powered-by": ["PHP/8.1.29"] },
      wordpress: { is_wp: false, evidence: null, wp_version: null },
    });
    assert.equal(eol.verdict, "eol");

    const future = buildVerdict({
      host: "example.com",
      httpCode: 200,
      headers: { "x-powered-by": ["PHP/8.6.1"] },
      wordpress: { is_wp: false, evidence: null, wp_version: null },
    });
    assert.equal(future.verdict, "unknown_version");
  });
});

describe("checkSite wiring", () => {
  it("forces https, drops the query, and probes /wp-json/ on the original host", async () => {
    const snippets = [];
    const result = await checkSite("http://ten-percent.co.uk/path?x=1", {
      fetchHeaders: async (url) => {
        assert.equal(url, "https://ten-percent.co.uk/path");
        return {
          httpCode: 200,
          finalUrl: url,
          headers: { server: ["Apache"], "x-powered-by": ["PHP/8.3.35"] },
        };
      },
      fetchSnippet: async (url) => {
        snippets.push(url);
        return { body: '{"namespaces":["wp/v2"]}' };
      },
    });
    assert.equal(result.verdict, "vulnerable");
    assert.equal(result.wordpress.is_wp, true);
    assert.equal(result.wordpress.evidence, "/wp-json/ REST API present");
    assert.deepEqual(snippets, ["https://ten-percent.co.uk/wp-json/"]);
  });

  it("does not fetch private, metadata, or obfuscated loopback addresses", async () => {
    for (const input of ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data", "http://2130706433/", "http://metadata.google.internal/", "http://printer.local/"]) {
      let called = false;
      const result = await checkSite(input, {
        fetchHeaders: async () => {
          called = true;
          return { httpCode: 200, headers: {} };
        },
      });
      assert.equal(called, false, input);
      assert.equal(result.verdict, "invalid", input);
    }
  });
});

describe("SSRF addresses", () => {
  it("blocks reserved ranges and allows public addresses", () => {
    for (const ip of ["127.0.0.1", "10.1.2.3", "169.254.169.254", "172.16.0.1", "192.168.0.1", "::1", "fd00::1", "::ffff:127.0.0.1"]) {
      assert.equal(isBlockedIp(ip), true, ip);
    }
    for (const ip of ["8.8.8.8", "93.184.216.34", "1.1.1.1"]) {
      assert.equal(isBlockedIp(ip), false, ip);
    }
  });

  it("normalizes a bare domain to https", () => {
    assert.equal(normalizeInput("example.com").href, "https://example.com/");
  });
});

describe("redirect safety", () => {
  it("does not request a redirect onto a metadata address", async () => {
    const calls = [];
    const result = await fetchHeaders("https://example.com/", {
      resolve: async (host) => {
        if (host === "169.254.169.254") throw new SsrfError("blocked");
        return { address: "93.184.216.34", family: 4 };
      },
      request: async ({ target, method }) => {
        calls.push({ href: target.href, method });
        return { httpCode: 302, headers: { location: ["http://169.254.169.254/latest/meta-data"] }, finalUrl: target.href };
      },
    });
    assert.equal(result.error, "redirect was not a public website");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].method, "HEAD");
  });
});

describe("passive HTTP", () => {
  it("sends HEAD with an empty body and the checker user agent", async () => {
    let method = "";
    let bytes = 0;
    let ua = "";
    const server = http.createServer((req, res) => {
      method = req.method;
      ua = req.headers["user-agent"];
      req.on("data", (chunk) => {
        bytes += chunk.length;
      });
      res.writeHead(200, { "X-Powered-By": "PHP/8.2.35", Server: "Apache" });
      res.end();
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    try {
      const response = await requestOnce({
        target: new URL(`http://127.0.0.1:${port}/health`),
        pin: { address: "127.0.0.1", family: 4 },
        method: "HEAD",
        timeoutMs: 2000,
        readBody: false,
      });
      assert.equal(method, "HEAD");
      assert.equal(bytes, 0);
      assert.equal(ua, UA);
      assert.equal(response.headers["x-powered-by"][0], "PHP/8.2.35");
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
