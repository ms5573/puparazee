"use strict";

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const handler = require("../api/check");

function mockReq(body, headers = {}) {
  const payload = Buffer.from(body);
  return {
    method: "POST",
    headers,
    socket: { remoteAddress: "203.0.113.10" },
    async *[Symbol.asyncIterator]() {
      yield payload;
    },
  };
}

function mockRes() {
  return {
    statusCode: 0,
    headers: {},
    body: "",
    writeHead(code, headers) {
      this.statusCode = code;
      this.headers = headers;
    },
    end(payload) {
      this.body = payload;
    },
    json() {
      return JSON.parse(this.body);
    },
  };
}

describe("POST /api/check", () => {
  beforeEach(() => handler.resetRateLimitForTests());

  it("rejects a private URL before any fetch", async () => {
    const req = mockReq(JSON.stringify({ url: "http://169.254.169.254/" }), { "x-real-ip": "203.0.113.20" });
    const res = mockRes();
    await handler(req, res);
    assert.equal(res.statusCode, 400);
    assert.equal(res.json().error, "blocked");
    assert.equal(res.headers["Cache-Control"], "no-store");
  });

  it("rejects a non-POST", async () => {
    const res = mockRes();
    await handler({ method: "GET", headers: {}, socket: {} }, res);
    assert.equal(res.statusCode, 405);
  });

  it("rate limits a repeated client", async () => {
    for (let i = 0; i < 8; i += 1) {
      const res = mockRes();
      await handler(mockReq(JSON.stringify({ url: "http://127.0.0.1/" }), { "x-real-ip": "203.0.113.30" }), res);
      assert.equal(res.statusCode, 400);
    }
    const limited = mockRes();
    await handler(mockReq(JSON.stringify({ url: "https://example.com" }), { "x-real-ip": "203.0.113.30" }), limited);
    assert.equal(limited.statusCode, 429);
  });
});
