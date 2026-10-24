"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { requestHeaders } = require("../lib/fetch-headers");

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

describe("requestHeaders", () => {
  it("sends GET with an empty body and returns headers without waiting for the body", async () => {
    let method = "";
    let bytes = 0;
    let finishedBody = false;
    let timer;
    const server = http.createServer((req, res) => {
      method = req.method;
      req.on("data", (chunk) => {
        bytes += chunk.length;
      });
      res.writeHead(200, {
        "X-Powered-By": "PHP/8.2.34",
        Server: "Apache",
        "X-Pingback": "https://example.com/xmlrpc.php",
      });
      res.write("x");
      timer = setTimeout(() => {
        finishedBody = true;
        res.end("x".repeat(1024 * 64));
      }, 4000);
    });
    const port = await listen(server);
    try {
      const started = Date.now();
      const response = await requestHeaders(new URL(`http://127.0.0.1:${port}/path?q=1`), { address: "127.0.0.1", family: 4 }, 2000);
      const elapsed = Date.now() - started;
      assert.equal(method, "GET");
      assert.equal(bytes, 0);
      assert.equal(finishedBody, false);
      assert.equal(response.statusCode, 200);
      assert.equal(response.headers["x-powered-by"], "PHP/8.2.34");
      assert.equal(response.headers["x-pingback"], "https://example.com/xmlrpc.php");
      assert.ok(elapsed < 1000, `waited ${elapsed}ms for headers`);
    } finally {
      clearTimeout(timer);
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
